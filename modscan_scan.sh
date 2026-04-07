#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# modscan_scan.sh — 无需加载内核模块的 DKOM 检测与模块加载干扰检测工具
#
# 检测内容：
#   1. modules_disabled sysctl（一次性开关，被 rootkit 设置后无法恢复）
#   2. /sys/module/ vs /proc/modules 一致性（DKOM list_del 攻击）
#   3. /proc/kallsyms 孤儿模块符号（被隐藏的模块仍有符号残留）
#   4. finit_module / init_module / load_module / tcp4_seq_show 等内联 patch 检测（需要 /proc/kcore）
#   5. 系统调用表指针劫持检测，含 getdents/getdents64（需要 /proc/kcore）
#   6. sig_enforce 状态
#   7. Skidmap 恶意软件特征（已知模块名、ld.so.preload、PAM 后门、cron 持久化）
#
# 用法: sudo bash modscan_scan.sh
#
# 退出码:
#   0  — 未发现任何异常指标
#   1  — 发现一个或多个异常指标
#   2  — 运行错误（非 root、工具缺失等）

set -euo pipefail

# ── 颜色输出 ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
BLU='\033[1;34m'
RST='\033[0m'

info()  { printf "${BLU}[*]${RST} %s\n" "$*"; }
ok()    { printf "${GRN}[+]${RST} %s\n" "$*"; }
warn()  { printf "${YEL}[!]${RST} %s\n" "$*"; }
alert() { printf "${RED}[ALERT]${RST} %s\n" "$*"; }

FINDINGS=0
flag() { FINDINGS=$(( FINDINGS + 1 )); }

# ── 权限检查 ─────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    printf "错误: 需要 root 权限\n" >&2
    exit 2
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 1: modules_disabled sysctl
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_modules_disabled() {
    local SYSCTL_PATH=/proc/sys/kernel/modules_disabled

    info "CHECK 1: modules_disabled sysctl"

    if [[ ! -r "$SYSCTL_PATH" ]]; then
        warn "  $SYSCTL_PATH 不可读（内核未启用 CONFIG_MODULES？）"
        return
    fi

    local val
    val=$(< "$SYSCTL_PATH")

    if [[ "$val" == "1" ]]; then
        alert "  modules_disabled=1 ─── 内核模块加载已被永久禁止！"
        alert "  这是单向开关：无法通过 sysctl 恢复，必须 kexec 或重启"
        flag
    else
        ok "  modules_disabled=0（正常）"
    fi

    # 同时检查 kexec 是否也被禁用
    local KEXEC_PATH=/proc/sys/kernel/kexec_load_disabled
    if [[ -r "$KEXEC_PATH" ]]; then
        local kval
        kval=$(< "$KEXEC_PATH")
        if [[ "$kval" == "1" ]]; then
            alert "  kexec_load_disabled=1 ─── kexec 也被禁用！恢复路径受限"
            flag
        else
            ok "  kexec_load_disabled=0（kexec 可用，可作为恢复路径）"
        fi
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 2: /sys/module/ vs /proc/modules 一致性（DKOM 检测）
#
# 原理：
#   rootkit 调用 list_del(&mod->list) 将模块从 modules 链表摘除后，
#   /proc/modules (lsmod) 看不到该模块，但 /sys/module/ 仍存在其目录。
#   这是因为 kobject/kset 路径独立于 modules 链表。
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_modules_consistency() {
    info "CHECK 2: /sys/module/ 与 /proc/modules 一致性（DKOM list_del 检测）"

    if [[ ! -d /sys/module ]]; then
        warn "  /sys/module 不可访问（sysfs 未挂载？）"
        return
    fi

    # 构建 /proc/modules 中的模块名集合
    declare -A proc_mods
    while read -r name _rest; do
        proc_mods["$name"]=1
    done < /proc/modules

    # 遍历 /sys/module/ 中的真实 LKM 目录
    # 判断标准：存在 initstate 文件（内核内建子系统没有此文件）
    local hidden=0
    for d in /sys/module/*/; do
        [[ -d "$d" ]] || continue
        local mname
        mname=$(basename "$d")

        # 过滤：只检查有 initstate 的（真正的 LKM）
        [[ -f "${d}initstate" ]] || continue

        if [[ -z "${proc_mods[$mname]+_}" ]]; then
            alert "  HIDDEN MODULE: '$mname'"
            alert "    → 存在于 /sys/module/ 但不在 /proc/modules 中（已被 DKOM 隐藏）"
            alert "    → 恢复: sudo insmod modscan.ko && echo 'restore $mname' > /proc/modscan"
            flag
            hidden=$(( hidden + 1 ))
        fi
    done

    if [[ $hidden -eq 0 ]]; then
        ok "  /sys/module/ 和 /proc/modules 一致（未发现 DKOM 隐藏模块）"
    else
        alert "  共发现 $hidden 个 DKOM 隐藏模块"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 3: /proc/kallsyms 孤儿模块引用
#
# 原理：
#   即使模块被从 modules 链表摘除，其符号通常仍保留在 /proc/kallsyms 中，
#   格式为：<addr> <type> <symbol> [module_name]
#   若方括号中的模块名不在 /proc/modules 里 → 该模块已被隐藏
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_kallsyms_orphans() {
    info "CHECK 3: /proc/kallsyms 孤儿模块符号"

    if [[ ! -r /proc/kallsyms ]]; then
        warn "  /proc/kallsyms 不可读"
        return
    fi

    # 使用 awk 一次性处理两个文件，避免 bash while 循环逐行读取 10万+ 行的性能问题
    # NR==FNR: 第一个文件 /proc/modules，记录已知模块名
    # NR!=FNR: 第二个文件 /proc/kallsyms，找 [modname] 列不在已知集合中的条目
    local result
    result=$(awk '
        NR == FNR {
            known[$1] = 1
            next
        }
        NF >= 4 && $4 ~ /^\[.+\]$/ {
            modname = substr($4, 2, length($4) - 2)
            if (!(modname in known)) {
                count[modname]++
                seen[modname] = 1
            }
        }
        END {
            for (m in seen)
                print count[m], m
        }
    ' /proc/modules /proc/kallsyms)

    if [[ -z "$result" ]]; then
        ok "  kallsyms 中未发现孤儿模块符号"
    else
        while read -r cnt modname; do
            alert "  ORPHAN MODULE: '$modname'（$cnt 个符号残留在 kallsyms 中，但不在 /proc/modules）"
            flag
        done <<< "$result"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 4 & 5: 内联 patch 与系统调用表劫持检测
#
# 通过 /proc/kcore 读取内核内存（需要 root，需要 CONFIG_PROC_KCORE=y）
# 使用 Python3 进行 ELF 解析（无需额外依赖）
#
# 检测目标：
#   - __x64_sys_finit_module : finit_module 系统调用入口
#   - __x64_sys_init_module  : init_module 系统调用入口
#   - load_module            : 核心模块加载函数
#   - sys_call_table[313]    : finit_module 系统调用表槽位
#
# 内联 patch 特征（x86-64）：
#   0xe9       = JMP rel32（最常见的 hook 跳转）
#   0xff 0x25  = JMP [rip+disp32]（间接跳转）
#   0xff 0xe?  = JMP reg（寄存器跳转）
#   0xcc       = INT3（ftrace/kprobe 替换，通常是正常的，但也可能是恶意的）
#
# 正常函数开头：
#   0xf3 0x0f 0x1e 0xfa = ENDBR64（IBT 保护，Linux 5.18+ 常见）
#   0x55                = PUSH RBP
#   0x41 0x5?           = PUSH R??
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_hooks_via_kcore() {
    info "CHECK 4+5: 系统调用内联 patch 与系统调用表劫持检测（via /proc/kcore）"

    if [[ ! -r /proc/kcore ]]; then
        warn "  /proc/kcore 不可读——跳过 hook 检测"
        warn "  （确保 CONFIG_PROC_KCORE=y，且以 root 运行）"
        return
    fi

    if ! command -v python3 &>/dev/null; then
        warn "  python3 未找到——跳过 hook 检测，可改用 modscan_kcore 工具"
        return
    fi

    local py_ret=0
    python3 - <<'PYEOF' || py_ret=$?
import struct, sys, os

KCORE = "/proc/kcore"
KSYMS = "/proc/kallsyms"

# ── 读取 /proc/kallsyms ──────────────────────────────────────────────────────
syms = {}
try:
    with open(KSYMS) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                syms[parts[2]] = int(parts[0], 16)
except PermissionError:
    print("  [!] /proc/kallsyms 不可读", file=sys.stderr)
    sys.exit(2)

def sym(name):
    return syms.get(name, 0)

# ── ELF64 /proc/kcore 读取器 ─────────────────────────────────────────────────
class KCore:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.segs = []
        hdr = self._pread(0, 64)
        if hdr[:4] != b'\x7fELF':
            raise ValueError("不是 ELF 文件")
        e_phoff     = struct.unpack_from('<Q', hdr, 32)[0]
        e_phentsize = struct.unpack_from('<H', hdr, 54)[0]
        e_phnum     = struct.unpack_from('<H', hdr, 56)[0]
        for i in range(e_phnum):
            ph = self._pread(e_phoff + i * e_phentsize, 56)
            p_type   = struct.unpack_from('<I', ph, 0)[0]
            if p_type != 1:  # PT_LOAD
                continue
            p_offset = struct.unpack_from('<Q', ph, 8)[0]
            p_vaddr  = struct.unpack_from('<Q', ph, 16)[0]
            p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            self.segs.append((p_vaddr, p_filesz, p_offset))

    def _pread(self, offset, n):
        import os
        return os.pread(self.f.fileno(), n, offset)

    def read(self, vaddr, n):
        for (va, sz, off) in self.segs:
            if va <= vaddr < va + sz and vaddr + n <= va + sz:
                data = self._pread(off + (vaddr - va), n)
                if len(data) == n:
                    return data
        return None

    def read_u64(self, vaddr):
        d = self.read(vaddr, 8)
        return struct.unpack_from('<Q', d)[0] if d else None

try:
    kc = KCore(KCORE)
except Exception as e:
    print(f"  [!] 无法打开 /proc/kcore: {e}", file=sys.stderr)
    sys.exit(2)

# ── 内核文本段边界（用于指针合法性检查）───────────────────────────────────────
stext = sym('_stext') or sym('startup_64') or 0
etext = sym('_etext') or 0

def in_ktext(addr):
    if stext and etext:
        return stext <= addr < etext
    return True  # 无法判断，假设合法

# ── 内联 patch 特征检测 ──────────────────────────────────────────────────────
def is_patched(b):
    """返回 (patched: bool, reason: str)"""
    if not b or len(b) < 2:
        return False, ""
    if b[0] == 0xe9:
        return True, "JMP rel32 (0xe9)"
    if b[0] == 0xff and b[1] == 0x25:
        return True, "JMP [rip+disp] (0xff 0x25)"
    if b[0] == 0xff and (b[1] & 0xf8) == 0xe0:
        return True, f"JMP reg (0xff {b[1]:02x})"
    # 0xcc 是 INT3，ftrace/kprobe 正常使用，但也可能是 rootkit
    # 0xe8 是 CALL，不是有效的函数开头 → 可疑
    if b[0] == 0xe8:
        return True, "CALL rel32 作为函数开头 (0xe8) — 可疑"
    return False, ""

findings = 0

# ── CHECK 4: 函数内联 patch 检测 ────────────────────────────────────────────
print("  [内联 patch 检测]")
targets = [
    ('__x64_sys_finit_module',         'finit_module 系统调用入口'),
    ('__x64_sys_init_module',          'init_module 系统调用入口'),
    ('load_module',                    '核心模块加载函数'),
    ('security_kernel_post_read_file', 'LSM post-read-file hook'),
    # Skidmap 特征目标：网络连接隐藏 & CPU 使用率伪造
    ('tcp4_seq_show',  'TCP4 连接列表（Skidmap 隐藏挖矿网络连接）'),
    ('udp4_seq_show',  'UDP4 连接列表（Skidmap 隐藏挖矿网络连接）'),
    ('tcp6_seq_show',  'TCP6 连接列表'),
    ('udp6_seq_show',  'UDP6 连接列表'),
    ('proc_stat_show', '/proc/stat 输出（Skidmap 伪造 CPU 空闲率）'),
]

for (symname, desc) in targets:
    addr = sym(symname)
    if not addr:
        print(f"    [-] {symname}: 不在 kallsyms（内核版本差异，可能正常）")
        continue
    data = kc.read(addr, 16)
    if data is None:
        print(f"    [?] {symname}: kcore 读取失败")
        continue
    patched, reason = is_patched(data)
    hex_preview = ' '.join(f'{x:02x}' for x in data[:8])
    if patched:
        print(f"\033[0;31m    [ALERT]\033[0m {symname} ({desc})")
        print(f"            地址: {addr:#x}  首字节: {hex_preview}")
        print(f"            特征: {reason} → 疑似被 HOOK！")
        findings += 1
    else:
        print(f"\033[0;32m    [+]\033[0m    {symname}: 正常 ({hex_preview}...)")

# ── CHECK 5: 系统调用表指针检测 ──────────────────────────────────────────────
print("\n  [系统调用表指针检测]")
sct_addr    = sym('sys_call_table')
finit_addr  = sym('__x64_sys_finit_module')
init_addr   = sym('__x64_sys_init_module')
gd_addr     = sym('__x64_sys_getdents')
gd64_addr   = sym('__x64_sys_getdents64')

SCT_CHECKS = [
    (313, '__x64_sys_finit_module',  finit_addr),  # __NR_finit_module  = 313
    (175, '__x64_sys_init_module',   init_addr),   # __NR_init_module   = 175
    # Skidmap 主要通过劫持这两个调用实现文件隐藏
    ( 78, '__x64_sys_getdents',      gd_addr),     # __NR_getdents      = 78
    (217, '__x64_sys_getdents64',    gd64_addr),   # __NR_getdents64    = 217
]

if not sct_addr:
    print("    [-] sys_call_table 不在 kallsyms（可能需要 CONFIG_KALLSYMS_ALL=y）")
else:
    for (nr, symname, expected) in SCT_CHECKS:
        if not expected:
            continue
        slot_va = sct_addr + nr * 8
        stored  = kc.read_u64(slot_va)
        if stored is None:
            print(f"    [?] sys_call_table[{nr}]: kcore 读取失败")
            continue
        if stored == expected:
            print(f"\033[0;32m    [+]\033[0m    sys_call_table[{nr}] ({symname}): 正常 ({stored:#x})")
        else:
            if not in_ktext(stored):
                print(f"\033[0;31m    [ALERT]\033[0m sys_call_table[{nr}] ({symname})")
                print(f"            存储值: {stored:#x}  期望值: {expected:#x}")
                print(f"            指针超出内核 .text 范围 → 系统调用表已被 HOOK！")
                findings += 1
            else:
                print(f"\033[1;33m    [!]\033[0m    sys_call_table[{nr}] ({symname})")
                print(f"            存储值: {stored:#x}  期望值: {expected:#x}")
                print(f"            指针在内核 .text 范围内，但与 kallsyms 不符（可能是 wrapper，请人工确认）")

sys.exit(1 if findings > 0 else 0)
PYEOF

    if [[ $py_ret -eq 1 ]]; then
        flag
    elif [[ $py_ret -eq 2 ]]; then
        warn "  hook 检测因错误中止"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 6: kset / sysfs 完整性交叉验证
#
# 原理：
#   通过 /proc/kcore 直接遍历内核内存中的 module_kset->list（比 /sys/module/ 更可信），
#   与 /sys/module/ 和 /proc/modules 交叉比对，检测三种篡改场景：
#
#   A. kcore kset 有 → /sys/module/ 没有：sysfs 条目被单独删除
#      （rootkit 调用 kernfs_remove() 或 kobject_del()）
#
#   B. /sys/module/ 有 → kcore kset 没有：kset 链表被直接篡改
#      （rootkit 对 kobj->entry 调用 list_del()，sysfs 残留）
#
#   C. kcore kset 有 → /proc/modules 和 /sys/module/ 都没有：
#      高级双重 DKOM，kset 中仍有残留（最隐蔽变种）
#
# struct kobject 内存布局（x86-64，Linux 4.x~6.x 稳定）：
#   offset  0 : const char *name  — 名字字符串指针
#   offset  8 : list_head entry   — kset 链表节点
#   offset 48 : kernfs_node *sd   — sysfs 节点指针（NULL = sysfs 已被删除）
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_kset_sysfs() {
    info "CHECK 6: module_kset / sysfs / proc 三源完整性交叉验证（via /proc/kcore）"

    if [[ ! -r /proc/kcore ]]; then
        warn "  /proc/kcore 不可读——跳过 kset/sysfs 交叉验证"
        return
    fi
    if ! command -v python3 &>/dev/null; then
        warn "  python3 未找到——跳过 kset/sysfs 交叉验证，可使用 modscan_kcore 工具"
        return
    fi

    local py_ret=0
    python3 - <<'PYEOF' || py_ret=$?
import struct, sys, os

KCORE = "/proc/kcore"
KSYMS = "/proc/kallsyms"

# ── 读取 kallsyms ────────────────────────────────────────────────────────────
syms = {}
try:
    with open(KSYMS) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 3:
                syms[parts[2]] = int(parts[0], 16)
except PermissionError:
    print("  [!] /proc/kallsyms 不可读", file=sys.stderr)
    sys.exit(2)

def sym(name):
    return syms.get(name, 0)

# ── /proc/kcore ELF 读取器（复用 CHECK 4+5 的同款实现）────────────────────
class KCore:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.segs = []
        hdr = self._pread(0, 64)
        if hdr[:4] != b'\x7fELF':
            raise ValueError("不是 ELF 文件")
        e_phoff     = struct.unpack_from('<Q', hdr, 32)[0]
        e_phentsize = struct.unpack_from('<H', hdr, 54)[0]
        e_phnum     = struct.unpack_from('<H', hdr, 56)[0]
        for i in range(e_phnum):
            ph = self._pread(e_phoff + i * e_phentsize, 56)
            p_type = struct.unpack_from('<I', ph, 0)[0]
            if p_type != 1:
                continue
            self.segs.append((
                struct.unpack_from('<Q', ph, 16)[0],   # p_vaddr
                struct.unpack_from('<Q', ph, 32)[0],   # p_filesz
                struct.unpack_from('<Q', ph, 8)[0],    # p_offset
            ))

    def _pread(self, offset, n):
        return os.pread(self.f.fileno(), n, offset)

    def read(self, vaddr, n):
        for (va, sz, off) in self.segs:
            if va <= vaddr < va + sz and vaddr + n <= va + sz:
                d = self._pread(off + (vaddr - va), n)
                if len(d) == n:
                    return d
        return None

    def read_u64(self, vaddr):
        d = self.read(vaddr, 8)
        return struct.unpack_from('<Q', d)[0] if d else None

try:
    kc = KCore(KCORE)
except Exception as e:
    print(f"  [!] 无法打开 /proc/kcore: {e}", file=sys.stderr)
    sys.exit(2)

# ── 遍历 module_kset->list ────────────────────────────────────────────────────
#
# struct kobject 偏移（x86-64，Linux 4.x~6.x）:
#   +0  : const char *name    (指向名字字符串的指针)
#   +8  : list_head  entry    (kset 链表节点, next@+8, prev@+16)
#   +48 : kernfs_node *sd     (sysfs 节点，NULL = sysfs 已删除)
#
# module_kset 是 static struct kset * 变量；kallsyms 给出指针变量地址，
# 需额外一次解引用才得到实际 kset。
# kset->list 是偏移 0 处的 list_head（sentinel）。
#
KOBJ_NAME_OFF = 0
KOBJ_ENTRY_OFF = 8
KOBJ_SD_OFF   = 48

kset_var = sym('module_kset')
if not kset_var:
    print("  [-] 'module_kset' 不在 kallsyms（需要 CONFIG_KALLSYMS_ALL=y）")
    sys.exit(2)

kset_ptr = kc.read_u64(kset_var)
if not kset_ptr:
    print("  [!] 无法读取 module_kset 指针")
    sys.exit(2)

sentinel = kset_ptr          # &kset->list
cur = kc.read_u64(sentinel)  # kset->list.next = 第一个 kobject 的 entry 地址
if cur is None:
    print("  [!] 无法读取 kset->list.next")
    sys.exit(2)

kset_names = {}   # name → (kobj_ptr, sd_ptr)
guard = 0
while cur != sentinel and guard < 4096:
    guard += 1
    kobj = cur - KOBJ_ENTRY_OFF  # 从 entry 字段退回 kobject 起始
    name_ptr = kc.read_u64(kobj + KOBJ_NAME_OFF)
    if name_ptr:
        raw = kc.read(name_ptr, 56)
        if raw:
            name = raw.split(b'\x00')[0].decode('ascii', errors='replace')
            if name and all(0x20 <= ord(c) < 0x7f for c in name):
                sd_ptr = kc.read_u64(kobj + KOBJ_SD_OFF) or 0
                kset_names[name] = (kobj, sd_ptr)
    next_ptr = kc.read_u64(cur)
    if next_ptr is None:
        break
    cur = next_ptr

print(f"    kcore kset 遍历结果: {len(kset_names)} 个模块 kobject")

# ── 读取 /sys/module/ 列表 ───────────────────────────────────────────────────
import os as _os
sysfs_mods = set()
try:
    for entry in _os.scandir('/sys/module'):
        if entry.is_dir() and _os.path.exists(f'/sys/module/{entry.name}/initstate'):
            sysfs_mods.add(entry.name)
except Exception as e:
    print(f"  [!] 无法扫描 /sys/module/: {e}", file=sys.stderr)

# ── 读取 /proc/modules 列表 ─────────────────────────────────────────────────
proc_mods = set()
try:
    with open('/proc/modules') as f:
        for line in f:
            proc_mods.add(line.split()[0])
except Exception as e:
    print(f"  [!] 无法读取 /proc/modules: {e}", file=sys.stderr)

print(f"    /sys/module/ 视图  : {len(sysfs_mods)} 个 LKM")
print(f"    /proc/modules 视图 : {len(proc_mods)} 个模块\n")

findings = 0

# ── A: kcore kset 有，但 /sys/module/ 没有 ──────────────────────────────────
for name, (kobj, sd) in kset_names.items():
    if name not in sysfs_mods:
        extra = ""
        if name not in proc_mods:
            extra = "（且不在 /proc/modules：高级双重 DKOM，kset 中仍有残留）"
        print(f"\033[0;31m    [ALERT]\033[0m SYSFS-TAMPER: '{name}' 在 kcore kset 中但 /sys/module/{name}/ 不存在！{extra}")
        print(f"            kobj地址: {kobj:#x}  sd指针: {sd:#x}")
        print(f"            → sysfs 条目已被单独删除（kernfs_remove / kobject_del）")
        findings += 1

# ── B: kcore kset 中 sd==NULL（sysfs 节点已删除但 kobject 仍在 kset）────────
for name, (kobj, sd) in kset_names.items():
    if sd == 0 and name in sysfs_mods:
        # sd is NULL but sysfs dir still visible — inconsistent state
        print(f"\033[0;31m    [ALERT]\033[0m SD-NULL: '{name}' 的 kobject.sd == NULL，但 /sys/module/{name}/ 仍存在")
        print(f"            kobj地址: {kobj:#x}")
        print(f"            → kernfs 节点已被 kobject_del() 清除，sysfs 目录残留（不一致状态）")
        findings += 1

# ── C: /sys/module/ 有，但 kcore kset 没有 ──────────────────────────────────
for name in sysfs_mods:
    if name not in kset_names:
        print(f"\033[0;31m    [ALERT]\033[0m KSET-TAMPER: '/sys/module/{name}/' 存在，但不在 kcore kset 链表中！")
        print(f"            → kset 链表节点被直接摘除（list_del on kobj->entry），sysfs 残留")
        findings += 1

if findings == 0:
    print("\033[0;32m    [+]\033[0m kset / sysfs / /proc/modules 三视图一致，未发现 kset/sysfs 篡改")

sys.exit(1 if findings > 0 else 0)
PYEOF

    if [[ $py_ret -eq 1 ]]; then
        flag
    elif [[ $py_ret -eq 2 ]]; then
        warn "  kset/sysfs 交叉验证因错误中止"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 7: 模块签名强制检测
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_sig_enforce() {
    info "CHECK 7: 模块签名强制 (sig_enforce)"

    local SIG=/proc/sys/kernel/sig_enforce
    if [[ ! -f "$SIG" ]]; then
        info "  sig_enforce 不存在（内核未启用 CONFIG_MODULE_SIG_FORCE）"
        return
    fi

    local val
    val=$(< "$SIG")
    if [[ "$val" == "1" ]]; then
        warn "  sig_enforce=1 ─── 只允许加载已签名的内核模块"
        warn "  如果无法加载检测工具，需确认签名配置（或使用 modscan_kcore 无模块检测）"
    else
        ok "  sig_enforce=0（不强制签名）"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CHECK 7: Skidmap 恶意软件特征检测
#
# Skidmap 是一种以加密货币挖矿为目的的 Linux rootkit，通过内核模块实现：
#   - 劫持 getdents64 隐藏挖矿相关文件（CHECK 4+5 已检测）
#   - 劫持 tcp4_seq_show 隐藏挖矿网络连接（CHECK 4+5 已检测）
#   - 使用已知伪装模块名（iproute、netlink、mstf 等）
#   - 替换 pam_unix.so 实现免密码登录后门
#   - 写入 /etc/ld.so.preload 实现用户态文件隐藏
#   - 在 cron 中写入持久化脚本
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_skidmap() {
    info "CHECK 7: Skidmap 恶意软件特征检测"

    # ── 7-1. 已知 Skidmap 内核模块名扫描 ─────────────────────────────────────
    info "  [7-1] 已知 Skidmap 内核模块名扫描（via /proc/kallsyms）"
    # 模块名来源：Trend Micro、AT&T Alien Labs 等公开样本分析报告
    local -a SKIDMAP_MODS=(iproute netlink mstf bcmap kaudited kbuild pc_keyb snd_floppy)
    local skid_mod_found=0

    if [[ -r /proc/kallsyms ]]; then
        # 构建 /proc/modules 中的已知模块集合（复用 CHECK 2 的逻辑）
        declare -A _proc_mods
        while read -r name _rest; do
            _proc_mods["$name"]=1
        done < /proc/modules

        # 从 kallsyms 提取所有 [modname] 字段，检查是否匹配 Skidmap 已知名
        local found_names
        found_names=$(awk '
            NF >= 4 && $4 ~ /^\[.+\]$/ {
                modname = substr($4, 2, length($4) - 2)
                seen[modname] = 1
            }
            END { for (m in seen) print m }
        ' /proc/kallsyms)

        for mname in $found_names; do
            for skid in "${SKIDMAP_MODS[@]}"; do
                if [[ "$mname" == "$skid" ]]; then
                    skid_mod_found=$(( skid_mod_found + 1 ))
                    if [[ -z "${_proc_mods[$mname]+_}" ]]; then
                        alert "  SKIDMAP 已知模块 '$mname': 符号在 kallsyms 中但不在 /proc/modules（已 DKOM 隐藏）"
                    else
                        alert "  SKIDMAP 已知模块 '$mname': 当前已加载（在 /proc/modules 中）"
                    fi
                    flag
                fi
            done
        done
    else
        warn "  /proc/kallsyms 不可读，跳过已知模块名扫描"
    fi

    if [[ $skid_mod_found -eq 0 ]]; then
        ok "  未发现已知 Skidmap 模块名"
    fi

    # ── 7-2. /etc/ld.so.preload 检测 ─────────────────────────────────────────
    info "  [7-2] /etc/ld.so.preload 检测（用户态文件隐藏后门）"
    # 部分 Skidmap 变种通过此文件预加载恶意共享库，实现用户态文件/进程隐藏
    if [[ -f /etc/ld.so.preload ]]; then
        if [[ ! -s /etc/ld.so.preload ]]; then
            warn "  /etc/ld.so.preload 存在但为空（可疑，正常系统通常不存在此文件）"
        else
            alert "  /etc/ld.so.preload 存在且非空！内容如下："
            while IFS= read -r line; do
                alert "    → $line"
            done < /etc/ld.so.preload
            flag
        fi
    else
        ok "  /etc/ld.so.preload 不存在（正常）"
    fi

    # ── 7-3. PAM 后门检测 ────────────────────────────────────────────────────
    info "  [7-3] PAM 后门检测（pam_unix.so 完整性）"
    # Skidmap 将 pam_unix.so 替换为恶意版本，使其接受任意密码
    # 恶意版体积通常远小于正常版（<50KB vs >80KB）
    local pam_file=""
    for p in /lib/security/pam_unix.so \
              /lib64/security/pam_unix.so \
              /lib/x86_64-linux-gnu/security/pam_unix.so \
              /usr/lib/x86_64-linux-gnu/security/pam_unix.so \
              /usr/lib/security/pam_unix.so; do
        [[ -f "$p" ]] && pam_file="$p" && break
    done

    if [[ -z "$pam_file" ]]; then
        warn "  未找到 pam_unix.so（非标准安装路径或未安装 PAM？）"
    else
        local pam_size
        pam_size=$(stat -c '%s' "$pam_file" 2>/dev/null || echo 0)
        local pam_mtime_sec
        pam_mtime_sec=$(stat -c '%Y' "$pam_file" 2>/dev/null || echo 0)
        local now_sec
        now_sec=$(date +%s)
        local age_hours=$(( (now_sec - pam_mtime_sec) / 3600 ))

        if (( pam_size > 0 && pam_size < 51200 )); then
            alert "  PAM: $pam_file 大小异常小（${pam_size} 字节 < 50KB）— 疑似被 Skidmap 替换！"
            flag
        elif (( age_hours < 48 )); then
            warn "  PAM: $pam_file 在 ${age_hours} 小时前被修改 — 请确认是否为正常系统更新"
        else
            ok "  PAM: $pam_file 大小=${pam_size}B  修改于 ${age_hours}h 前（正常）"
        fi
    fi

    # ── 7-4. Skidmap cron 持久化检测 ─────────────────────────────────────────
    info "  [7-4] Skidmap cron 持久化检测"
    # Skidmap 在 /etc/cron.d/ 中写入使用其伪装模块名命名的 cron 文件
    local -a SKIDMAP_CRON_FILES=(
        /etc/cron.d/iproute
        /etc/cron.d/netlink
        /etc/cron.d/kbuild
        /etc/cron.d/mstf
        /etc/cron.d/bcmap
    )
    local cron_found=0
    for cf in "${SKIDMAP_CRON_FILES[@]}"; do
        if [[ -f "$cf" ]]; then
            alert "  CRON: 发现 Skidmap 特征 cron 文件: $cf"
            flag
            cron_found=$(( cron_found + 1 ))
        fi
    done
    if [[ $cron_found -eq 0 ]]; then
        ok "  未发现 Skidmap 特征 cron 文件"
    fi
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 主流程
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
printf "\n${BLU}╔══════════════════════════════════════════╗${RST}\n"
printf "${BLU}║      ModScan Shell Scanner               ║${RST}\n"
printf "${BLU}╚══════════════════════════════════════════╝${RST}\n"
printf "  内核版本: %s\n" "$(uname -r)"
printf "  检测时间: %s\n\n" "$(date)"

check_modules_disabled
echo
check_modules_consistency
echo
check_kallsyms_orphans
echo
check_hooks_via_kcore
echo
check_kset_sysfs
echo
check_sig_enforce
echo
check_skidmap

echo
printf "${BLU}────────────────────────────────────────────${RST}\n"
if [[ $FINDINGS -eq 0 ]]; then
    ok "结论：未发现异常指标（共 0 项告警）"
    printf "\n"
    exit 0
else
    alert "结论：发现 ${FINDINGS} 项异常指标，详见上方 [ALERT] 行"
    printf "\n${YEL}还原建议：${RST}\n"
    printf "  方案A（推荐）：若 modscan.ko 已加载\n"
    printf "    echo 'restore <模块名>' > /proc/modscan\n"
    printf "\n"
    printf "  方案B：若模块加载被禁用，但 kexec 可用\n"
    printf "    kexec -l /boot/vmlinuz --initrd=/boot/initramfs.img --reuse-cmdline\n"
    printf "    kexec -e   # 切换到新内核，rootkit 消失\n"
    printf "\n"
    printf "  方案C：若内核启用了 CONFIG_KDB\n"
    printf "    echo g > /proc/sysrq-trigger   # 进入 kdb\n"
    printf "    kdb> lsmod                     # 查看模块（包括隐藏的）\n"
    printf "    kdb> mm <list.next> <value>    # 手动修改链表指针\n"
    printf "\n"
    printf "  方案D：从可信介质重启\n"
    exit 1
fi
