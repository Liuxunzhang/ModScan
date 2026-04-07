#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# modscan_scan.sh — 无需加载内核模块的 DKOM 检测与模块加载干扰检测工具
#
# 检测内容：
#   1. modules_disabled sysctl（一次性开关，被 rootkit 设置后无法恢复）
#   2. /sys/module/ vs /proc/modules 一致性（DKOM list_del 攻击）
#   3. /proc/kallsyms 孤儿模块符号（被隐藏的模块仍有符号残留）
#   4. finit_module / init_module / load_module 内联 patch 检测（需要 /proc/kcore）
#   5. 系统调用表指针劫持检测（需要 /proc/kcore）
#   6. sig_enforce 状态
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
    ('__x64_sys_finit_module', 'finit_module 系统调用入口'),
    ('__x64_sys_init_module',  'init_module 系统调用入口'),
    ('load_module',            '核心模块加载函数'),
    ('security_kernel_post_read_file', 'LSM post-read-file hook'),
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

SCT_CHECKS = [
    (313, '__x64_sys_finit_module', finit_addr),  # __NR_finit_module = 313
    (175, '__x64_sys_init_module',  init_addr),   # __NR_init_module  = 175
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
# CHECK 6: 模块签名强制检测
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
check_sig_enforce() {
    info "CHECK 6: 模块签名强制 (sig_enforce)"

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
check_sig_enforce

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
