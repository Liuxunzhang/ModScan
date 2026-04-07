// SPDX-License-Identifier: GPL-2.0
/*
 * modscan_kcore.c — 无需加载内核模块的深层内核扫描器
 *
 * 通过 /proc/kcore（内核内存的只读 ELF 视图）直接读取内核数据结构，
 * 在不加载任何 .ko 文件的情况下检测 DKOM 隐藏模块及模块加载路径劫持。
 *
 * 检测内容：
 *   1. modules_disabled 标志
 *   2. DKOM list_del 隐藏模块（walk modules 链表，与 /sys/module/ 对比）
 *   3. finit_module / init_module / load_module / tcp4_seq_show 等内联 patch
 *   4. 系统调用表指针劫持 (sys_call_table[313/175/78/217])
 *   5. Skidmap 恶意软件特征（已知模块名、getdents64 hook、PAM 后门、ld.so.preload）
 *
 * struct module 布局（x86-64，无 __randomize_layout，跨内核版本稳定）：
 *   offset  0: enum module_state state   (4 bytes)
 *   offset  4: (padding)                 (4 bytes)
 *   offset  8: struct list_head list     (16 bytes: next@+0, prev@+8)
 *   offset 24: char name[56]
 *
 * 编译: gcc -O2 -Wall -Wextra -o modscan_kcore modscan_kcore.c
 * 运行: sudo ./modscan_kcore
 *
 * 退出码:
 *   0 — 未发现异常
 *   1 — 发现一个或多个异常
 *   2 — 运行时错误（权限不足、内核配置缺失等）
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* ─── ANSI 颜色 ─────────────────────────────────────────────────────────── */
#define C_RED  "\033[0;31m"
#define C_YEL  "\033[1;33m"
#define C_GRN  "\033[0;32m"
#define C_BLU  "\033[1;34m"
#define C_RST  "\033[0m"

static void info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(C_BLU "[*]" C_RST " "); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
static void ok(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(C_GRN "[+]" C_RST " "); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
static void warn(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(C_YEL "[!]" C_RST " "); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}
static void alert(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(C_RED "[ALERT]" C_RST " "); vprintf(fmt, ap); printf("\n");
    va_end(ap);
}

static int g_findings = 0;
#define FINDING() (g_findings++)

/* ─── struct module 布局常量（x86-64，稳定跨版本）────────────────────────── */
#define MODULE_STATE_OFF     0   /* enum module_state */
#define MODULE_LIST_NEXT_OFF 8   /* list_head.next (list is at offset 8) */
#define MODULE_LIST_PREV_OFF 16  /* list_head.prev */
#define MODULE_NAME_OFF      24  /* char name[MODULE_NAME_LEN] */
#define MODULE_NAME_LEN      56

/* ─── /proc/kallsyms 符号表 ─────────────────────────────────────────────── */
#define KSYM_HASH_BITS  14
#define KSYM_HASH_SIZE  (1 << KSYM_HASH_BITS)
#define KSYM_HASH_MASK  (KSYM_HASH_SIZE - 1)
#define KSYM_MAX        200000   /* 最大符号数 */

typedef struct ksym_entry {
    char     *name;
    uint64_t  addr;
    struct ksym_entry *next; /* hash chain */
} ksym_entry_t;

static ksym_entry_t *ksym_hash[KSYM_HASH_SIZE];
static ksym_entry_t  ksym_pool[KSYM_MAX];
static int           ksym_count;

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 0x811c9dc5u;
    while (*s)
        h = (h ^ (uint8_t)*s++) * 0x01000193u;
    return h;
}

static bool parse_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        warn("无法打开 /proc/kallsyms: %s", strerror(errno));
        return false;
    }

    char line[256];
    while (fgets(line, sizeof(line), f) && ksym_count < KSYM_MAX) {
        uint64_t addr;
        char     type[4], name[128];
        if (sscanf(line, "%lx %3s %127s", &addr, type, name) != 3)
            continue;
        if (addr == 0)
            continue;

        ksym_entry_t *e = &ksym_pool[ksym_count++];
        e->name = strdup(name);
        e->addr = addr;

        uint32_t h = fnv1a(name) & KSYM_HASH_MASK;
        e->next       = ksym_hash[h];
        ksym_hash[h]  = e;
    }
    fclose(f);
    return true;
}

static uint64_t sym_addr(const char *name)
{
    uint32_t h = fnv1a(name) & KSYM_HASH_MASK;
    for (ksym_entry_t *e = ksym_hash[h]; e; e = e->next)
        if (strcmp(e->name, name) == 0)
            return e->addr;
    return 0;
}

/* ─── /proc/kcore ELF 读取器 ─────────────────────────────────────────────── */
#define MAX_SEGS 128

typedef struct {
    uint64_t vaddr;
    uint64_t filesz;
    uint64_t file_offset;
} kseg_t;

static kseg_t ksegs[MAX_SEGS];
static int    nksegs;
static int    kcore_fd = -1;

static bool kcore_open(void)
{
    kcore_fd = open("/proc/kcore", O_RDONLY);
    if (kcore_fd < 0) {
        warn("无法打开 /proc/kcore: %s", strerror(errno));
        warn("  需要 root 权限且内核启用了 CONFIG_PROC_KCORE=y");
        return false;
    }

    Elf64_Ehdr ehdr;
    if (pread(kcore_fd, &ehdr, sizeof(ehdr), 0) != sizeof(ehdr)) {
        warn("读取 ELF 头失败");
        return false;
    }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        warn("/proc/kcore 不是有效的 ELF 文件");
        return false;
    }

    nksegs = 0;
    for (int i = 0; i < ehdr.e_phnum && nksegs < MAX_SEGS; i++) {
        Elf64_Phdr phdr;
        if (pread(kcore_fd, &phdr, sizeof(phdr),
                  ehdr.e_phoff + (off_t)i * ehdr.e_phentsize) != sizeof(phdr))
            continue;
        if (phdr.p_type != PT_LOAD)
            continue;
        ksegs[nksegs].vaddr       = phdr.p_vaddr;
        ksegs[nksegs].filesz      = phdr.p_filesz;
        ksegs[nksegs].file_offset = phdr.p_offset;
        nksegs++;
    }
    return nksegs > 0;
}

static ssize_t kcore_read(uint64_t vaddr, void *buf, size_t len)
{
    for (int i = 0; i < nksegs; i++) {
        if (vaddr >= ksegs[i].vaddr &&
            vaddr + len <= ksegs[i].vaddr + ksegs[i].filesz) {
            off_t foff = (off_t)(ksegs[i].file_offset + (vaddr - ksegs[i].vaddr));
            ssize_t n  = pread(kcore_fd, buf, len, foff);
            return n;
        }
    }
    errno = EFAULT;
    return -1;
}

static bool kcore_read_u64(uint64_t vaddr, uint64_t *out)
{
    return kcore_read(vaddr, out, 8) == 8;
}

/* ─── CHECK 1: modules_disabled ─────────────────────────────────────────── */
static void check_modules_disabled(void)
{
    info("CHECK 1: modules_disabled 状态");

    /* 方法1: 读取 sysctl procfs */
    {
        FILE *f = fopen("/proc/sys/kernel/modules_disabled", "r");
        if (f) {
            int val = 0;
            fscanf(f, "%d", &val);
            fclose(f);
            if (val == 1) {
                alert("  modules_disabled=1 — 模块加载已被永久禁止！");
                FINDING();
            } else {
                ok("  modules_disabled=0（正常）");
            }
        }
    }

    /* 方法2: 通过 kcore 直接读取内核变量（更难被篡改的 procfs 伪造） */
    uint64_t md_addr = sym_addr("modules_disabled");
    if (md_addr) {
        int32_t val = 0;
        if (kcore_read(md_addr, &val, 4) == 4) {
            if (val != 0) {
                alert("  kcore 读取: modules_disabled=%d (addr=%#lx)",
                      val, (unsigned long)md_addr);
                /* 如果 procfs 与 kcore 不一致，说明 procfs 被篡改 */
            } else {
                ok("  kcore 确认: modules_disabled=0 (addr=%#lx)",
                   (unsigned long)md_addr);
            }
        }
    }

    /* kexec 是否也被禁用 */
    FILE *f = fopen("/proc/sys/kernel/kexec_load_disabled", "r");
    if (f) {
        int val = 0;
        fscanf(f, "%d", &val);
        fclose(f);
        if (val == 1) {
            alert("  kexec_load_disabled=1 — kexec 恢复路径被封锁！");
            FINDING();
        } else {
            ok("  kexec_load_disabled=0（kexec 可用）");
        }
    }
}

/* ─── CHECK 2: 走 modules 链表，与 /sys/module/ 对比 ────────────────────── */

#define MAX_MODULES 1024

typedef struct {
    char     name[MODULE_NAME_LEN];
    uint64_t mod_addr;
} modinfo_t;

static modinfo_t kcore_modlist[MAX_MODULES];
static int       kcore_modlist_n;

static modinfo_t sysfs_modlist[MAX_MODULES];
static int       sysfs_modlist_n;

static modinfo_t procmod_list[MAX_MODULES];
static int       procmod_list_n;

/*
 * walk_module_list() — 通过 kcore 遍历 modules 链表
 *
 * "modules" 符号是链表哨兵 (LIST_HEAD sentinel)，其地址来自 kallsyms。
 * 遍历：
 *   1. 读 modules.next → 第一个 struct module 的 list.next 指针
 *   2. struct module * = list.next 指针值 - MODULE_LIST_NEXT_OFF（即减去8）
 *   3. 读 mod->name at offset 24
 *   4. 读 mod->list.next 继续遍历，直到回到哨兵地址
 */
static int walk_module_list(uint64_t modules_head_addr)
{
    uint64_t cur;
    int n = 0;

    if (!kcore_read_u64(modules_head_addr, &cur)) {
        warn("  无法读取 modules 链表头: %s", strerror(errno));
        return -1;
    }

    while (cur != modules_head_addr && n < MAX_MODULES) {
        /* cur 是 list_head.next，减去 list 在 struct module 中的偏移 */
        uint64_t mod_addr = cur - MODULE_LIST_NEXT_OFF + MODULE_STATE_OFF;
        /* 实际: MODULE_LIST_OFF = 8, 所以 mod_addr = cur - 8 */

        char name[MODULE_NAME_LEN] = {0};
        if (kcore_read(mod_addr + MODULE_NAME_OFF, name, MODULE_NAME_LEN - 1) < 0)
            break;
        name[MODULE_NAME_LEN - 1] = '\0';

        /* 基本合法性检查：名字不能全为 NUL 或不可打印 */
        bool valid = false;
        for (int i = 0; i < (int)sizeof(name) && name[i]; i++) {
            if (name[i] >= 0x20 && name[i] < 0x7f) { valid = true; break; }
        }
        if (!valid)
            break;

        strncpy(kcore_modlist[n].name, name, MODULE_NAME_LEN - 1);
        kcore_modlist[n].mod_addr = mod_addr;
        n++;

        /* 读取下一个节点 */
        if (!kcore_read_u64(cur, &cur))
            break;
    }

    return n;
}

/* 收集 /sys/module/ 中有 initstate 文件的真实 LKM */
static int scan_sysfs_modules(void)
{
    DIR *d = opendir("/sys/module");
    if (!d) {
        warn("  无法打开 /sys/module: %s", strerror(errno));
        return -1;
    }

    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < MAX_MODULES) {
        if (de->d_name[0] == '.')
            continue;
        /* 只统计有 initstate 文件的目录（真正 LKM） */
        char path[512];
        snprintf(path, sizeof(path), "/sys/module/%s/initstate", de->d_name);
        if (access(path, F_OK) != 0)
            continue;
        strncpy(sysfs_modlist[n].name, de->d_name, MODULE_NAME_LEN - 1);
        sysfs_modlist[n].name[MODULE_NAME_LEN - 1] = '\0';
        n++;
    }
    closedir(d);
    return n;
}

/* 收集 /proc/modules 中的模块名 */
static int read_proc_modules(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f) {
        warn("  无法打开 /proc/modules: %s", strerror(errno));
        return -1;
    }
    int n = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && n < MAX_MODULES) {
        char name[MODULE_NAME_LEN] = {0};
        if (sscanf(line, "%55s", name) == 1) {
            strncpy(procmod_list[n].name, name, MODULE_NAME_LEN - 1);
            n++;
        }
    }
    fclose(f);
    return n;
}

static bool name_in_list(const char *name, modinfo_t *list, int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(list[i].name, name) == 0)
            return true;
    return false;
}

static void check_hidden_modules(void)
{
    info("CHECK 2: DKOM 隐藏模块检测（walk modules 链表 + /sys/module/ 对比）");

    uint64_t modules_addr = sym_addr("modules");
    if (!modules_addr) {
        warn("  'modules' 符号不在 kallsyms（需要 CONFIG_KALLSYMS_ALL=y）");
        warn("  回退到 /sys/module/ 与 /proc/modules 对比");
        modules_addr = 0;
    }

    /* 收集三种视图 */
    if (modules_addr) {
        kcore_modlist_n = walk_module_list(modules_addr);
        if (kcore_modlist_n < 0) {
            warn("  kcore 链表遍历失败，回退到 /proc/modules");
            kcore_modlist_n = 0;
        } else {
            printf("    kcore 链表遍历到 %d 个模块\n", kcore_modlist_n);
        }
    }

    sysfs_modlist_n = scan_sysfs_modules();
    procmod_list_n  = read_proc_modules();

    if (sysfs_modlist_n < 0 || procmod_list_n < 0)
        return;

    printf("    /sys/module/ 共 %d 个 LKM，/proc/modules 共 %d 个模块\n",
           sysfs_modlist_n, procmod_list_n);

    /* ── 检测1: 在 /sys/module/ 但不在 /proc/modules → DKOM 隐藏 ── */
    int hidden = 0;
    for (int i = 0; i < sysfs_modlist_n; i++) {
        if (!name_in_list(sysfs_modlist[i].name, procmod_list, procmod_list_n)) {
            alert("  HIDDEN: '%s' 在 /sys/module/ 但不在 /proc/modules（DKOM 隐藏）",
                  sysfs_modlist[i].name);
            hidden++;
            FINDING();
        }
    }

    /* ── 检测2: kcore 链表遍历的结果与 /sys/module/ 对比（更深层验证）── */
    if (kcore_modlist_n > 0) {
        for (int i = 0; i < sysfs_modlist_n; i++) {
            bool in_kcore = name_in_list(sysfs_modlist[i].name,
                                         kcore_modlist, kcore_modlist_n);
            bool in_proc  = name_in_list(sysfs_modlist[i].name,
                                         procmod_list, procmod_list_n);
            if (!in_kcore && !in_proc) {
                alert("  CONFIRMED HIDDEN: '%s' 在 sysfs 中但不在 kcore 链表 AND /proc/modules",
                      sysfs_modlist[i].name);
            } else if (!in_kcore && in_proc) {
                warn("  INCONSISTENCY: '%s' 在 /proc/modules 中但不在 kcore 链表（可能 /proc/modules 被篡改）",
                     sysfs_modlist[i].name);
                FINDING();
            }
        }

        /* ── 检测3: /proc/modules 有，但 kcore 链表没有 → /proc/modules 被伪造 ── */
        for (int i = 0; i < procmod_list_n; i++) {
            if (!name_in_list(procmod_list[i].name, kcore_modlist, kcore_modlist_n)) {
                warn("  PHANTOM: '%s' 在 /proc/modules 中但不在 kcore 链表",
                     procmod_list[i].name);
                warn("           /proc/modules 可能被 rootkit 篡改！");
                FINDING();
            }
        }
    }

    if (hidden == 0 && g_findings == 0)
        ok("  未发现 DKOM 隐藏模块");
}

/* ─── CHECK 3: 内联 patch 与系统调用表劫持 ──────────────────────────────── */

/* x86-64 函数开头的可疑字节序列 */
static bool is_inline_patched(const uint8_t *b, int len, const char **reason)
{
    if (len < 2) return false;

    static const char *r;
    if (b[0] == 0xe9)
        { r = "JMP rel32 (0xe9)"; *reason = r; return true; }
    if (b[0] == 0xff && b[1] == 0x25)
        { r = "JMP [rip+disp32] (0xff 0x25)"; *reason = r; return true; }
    if (b[0] == 0xff && (b[1] & 0xf8) == 0xe0)
        { r = "JMP reg (0xff 0xe?)"; *reason = r; return true; }
    if (b[0] == 0xe8)
        { r = "CALL rel32 作为函数开头 (0xe8)"; *reason = r; return true; }
    return false;
}

static void check_function_integrity(void)
{
    info("CHECK 3: 内核函数内联 patch 检测");

    static const struct {
        const char *symname;
        const char *desc;
    } targets[] = {
        { "__x64_sys_finit_module",          "finit_module 系统调用入口"                    },
        { "__x64_sys_init_module",           "init_module 系统调用入口"                     },
        { "load_module",                     "核心模块加载函数"                              },
        { "security_kernel_post_read_file",  "LSM post-read-file hook"                    },
        /* Skidmap 特征目标：网络连接隐藏 & CPU 使用率伪造 */
        { "tcp4_seq_show",                   "TCP4 连接列表（Skidmap 隐藏挖矿网络连接）"     },
        { "udp4_seq_show",                   "UDP4 连接列表（Skidmap 隐藏挖矿网络连接）"     },
        { "tcp6_seq_show",                   "TCP6 连接列表"                                },
        { "udp6_seq_show",                   "UDP6 连接列表"                                },
        { "proc_stat_show",                  "/proc/stat 输出（Skidmap 伪造 CPU 空闲率）"   },
        { NULL, NULL }
    };

    for (int i = 0; targets[i].symname; i++) {
        uint64_t addr = sym_addr(targets[i].symname);
        if (!addr) {
            printf("    [-] %-40s 不在 kallsyms\n", targets[i].symname);
            continue;
        }

        uint8_t buf[16];
        if (kcore_read(addr, buf, sizeof(buf)) != (ssize_t)sizeof(buf)) {
            printf("    [?] %-40s kcore 读取失败 (addr=%#lx)\n",
                   targets[i].symname, (unsigned long)addr);
            continue;
        }

        char hex[64] = {0};
        for (int j = 0; j < 8; j++)
            snprintf(hex + j*3, 4, "%02x ", buf[j]);

        const char *reason = NULL;
        if (is_inline_patched(buf, sizeof(buf), &reason)) {
            alert("  %-40s 疑似 HOOK！", targets[i].symname);
            printf("       描述: %s\n", targets[i].desc);
            printf("       地址: %#lx  首字节: %s\n",
                   (unsigned long)addr, hex);
            printf("       特征: %s\n", reason);
            FINDING();
        } else {
            ok("  %-40s 正常  (%s...)", targets[i].symname, hex);
        }
    }
}

static void check_syscall_table(void)
{
    info("CHECK 4: 系统调用表指针完整性");

    uint64_t sct = sym_addr("sys_call_table");
    if (!sct) {
        warn("  sys_call_table 不在 kallsyms（需要 CONFIG_KALLSYMS_ALL=y）");
        return;
    }

    /* 内核 .text 范围 */
    uint64_t stext = sym_addr("_stext");
    uint64_t etext = sym_addr("_etext");

    static const struct {
        int      nr;
        const char *symname;
        const char *desc;
    } checks[] = {
        { 313, "__x64_sys_finit_module",  "finit_module  (#313)"  },
        { 175, "__x64_sys_init_module",   "init_module   (#175)"  },
        /* Skidmap 主要通过劫持这两个系统调用隐藏文件 */
        {  78, "__x64_sys_getdents",      "getdents      (#78)"   },
        { 217, "__x64_sys_getdents64",    "getdents64    (#217)"  },
        {   0, NULL, NULL }
    };

    for (int i = 0; checks[i].symname; i++) {
        uint64_t expected = sym_addr(checks[i].symname);
        if (!expected) {
            printf("    [-] %s: 符号不在 kallsyms\n", checks[i].symname);
            continue;
        }

        uint64_t slot_va = sct + (uint64_t)checks[i].nr * 8;
        uint64_t stored  = 0;
        if (!kcore_read_u64(slot_va, &stored)) {
            printf("    [?] sys_call_table[%d]: kcore 读取失败\n", checks[i].nr);
            continue;
        }

        if (stored == expected) {
            ok("  sys_call_table[%d] (%s): 正常 (%#lx)",
               checks[i].nr, checks[i].desc, (unsigned long)stored);
        } else {
            bool outside_text = stext && etext &&
                                (stored < stext || stored >= etext);
            if (outside_text) {
                alert("  sys_call_table[%d] (%s): 指针超出内核 .text！",
                      checks[i].nr, checks[i].desc);
                printf("       存储值: %#lx  期望值: %#lx\n",
                       (unsigned long)stored, (unsigned long)expected);
                printf("       .text 范围: [%#lx, %#lx)\n",
                       (unsigned long)stext, (unsigned long)etext);
                printf("       → 系统调用表已被 HOOK\n");
                FINDING();
            } else {
                warn("  sys_call_table[%d] (%s): 值与 kallsyms 不符",
                     checks[i].nr, checks[i].desc);
                printf("       存储值: %#lx  期望值: %#lx\n",
                       (unsigned long)stored, (unsigned long)expected);
                printf("       指针在 .text 范围内，可能是正常的 wrapper，请人工确认\n");
            }
        }
    }
}

/* ─── CHECK 5: Skidmap 恶意软件特征检测 ─────────────────────────────────── */
/*
 * Skidmap 是一种以加密货币挖矿为目的的 Linux rootkit，其内核模块通过以下手段隐藏：
 *   - 劫持 getdents64 系统调用（已在 CHECK 4 中检测）
 *   - 劫持 tcp4/udp4_seq_show 隐藏挖矿网络连接（已在 CHECK 3 中检测）
 *   - 使用一批已知的伪装模块名（如 iproute、netlink、mstf 等）
 *   - 替换 pam_unix.so 实现免密登录后门
 *   - 写入 /etc/ld.so.preload 实现用户态文件隐藏
 */
static void check_skidmap_indicators(void)
{
    info("CHECK 5: Skidmap 恶意软件特征检测");

    /* ── 1. 已知 Skidmap 内核模块名扫描（via /proc/kallsyms）────────────── */
    printf("  [1] 已知 Skidmap 内核模块名扫描\n");

    /*
     * 这些模块名来自已公开的 Skidmap 样本分析报告（Trend Micro、AT&T Alien Labs 等）：
     *   iproute   — 伪装成网络路由模块，是最常见的 Skidmap 主模块名
     *   netlink   — 伪装成内核 netlink 通信模块
     *   mstf      — 早期变种使用的模块名
     *   bcmap     — 区块链相关，用于与 C2 通信
     *   kaudited  — 伪装成内核审计模块（kauditd）
     *   kbuild    — 伪装成内核构建模块
     *   pc_keyb   — 伪装成键盘驱动
     *   snd_floppy— 伪装成声卡/软驱驱动
     */
    static const char * const skidmap_mods[] = {
        "iproute", "netlink", "mstf", "bcmap",
        "kaudited", "kbuild", "pc_keyb", "snd_floppy",
        NULL
    };
    /* 记录每个名字是否已上报，避免重复告警 */
    bool reported[8] = {false};
    int  skid_found  = 0;

    FILE *kf = fopen("/proc/kallsyms", "r");
    if (!kf) {
        warn("  无法打开 /proc/kallsyms，跳过已知模块名扫描");
    } else {
        char line[256];
        while (fgets(line, sizeof(line), kf)) {
            /* 在行末查找 [modname] 字段 */
            char *lb = strchr(line, '[');
            char *rb = lb ? strchr(lb + 1, ']') : NULL;
            if (!lb || !rb) continue;
            int   mlen = (int)(rb - lb - 1);
            if (mlen <= 0 || mlen >= 56) continue;

            char mname[56];
            memcpy(mname, lb + 1, (size_t)mlen);
            mname[mlen] = '\0';

            for (int i = 0; skidmap_mods[i]; i++) {
                if (reported[i]) continue;
                if (strcmp(mname, skidmap_mods[i]) != 0) continue;

                reported[i] = true;
                skid_found++;
                bool in_proc  = name_in_list(mname, procmod_list,  procmod_list_n);
                bool in_sysfs = name_in_list(mname, sysfs_modlist, sysfs_modlist_n);

                if (!in_proc) {
                    alert("  SKIDMAP 已知模块 '%s': 符号存在于 kallsyms"
                          " 但不在 /proc/modules（已通过 DKOM 隐藏）", mname);
                } else if (!in_sysfs) {
                    alert("  SKIDMAP 已知模块 '%s': 在 /proc/modules"
                          " 但不在 /sys/module/（异常状态）", mname);
                } else {
                    alert("  SKIDMAP 已知模块 '%s': 当前已加载！", mname);
                }
                FINDING();
            }
        }
        fclose(kf);
    }
    if (skid_found == 0)
        ok("  未发现已知 Skidmap 模块名");

    /* ── 2. /etc/ld.so.preload 检测 ─────────────────────────────────────── */
    printf("\n  [2] /etc/ld.so.preload 检测（用户态文件隐藏后门）\n");
    /*
     * Skidmap 及其他 rootkit 有时会向 /etc/ld.so.preload 写入恶意共享库路径，
     * 使所有动态链接程序在启动时预加载该库，从而实现用户态的文件/进程隐藏。
     */
    {
        struct stat pst;
        if (stat("/etc/ld.so.preload", &pst) == 0) {
            if (pst.st_size == 0) {
                warn("  /etc/ld.so.preload 存在但为空文件（可疑，正常系统通常不存在此文件）");
            } else {
                FILE *pf = fopen("/etc/ld.so.preload", "r");
                if (pf) {
                    char buf[4096] = {0};
                    size_t n = fread(buf, 1, sizeof(buf) - 1, pf);
                    fclose(pf);
                    buf[n] = '\0';
                    alert("  /etc/ld.so.preload 存在且非空！内容:");
                    /* 逐行打印，每行加缩进 */
                    char *line = buf, *nl;
                    while ((nl = strchr(line, '\n')) != NULL) {
                        *nl = '\0';
                        if (*line)
                            alert("    → %s", line);
                        line = nl + 1;
                    }
                    if (*line)
                        alert("    → %s", line);
                    FINDING();
                }
            }
        } else {
            ok("  /etc/ld.so.preload 不存在（正常）");
        }
    }

    /* ── 3. PAM 后门检测 ─────────────────────────────────────────────────── */
    printf("\n  [3] PAM 后门检测（pam_unix.so 完整性）\n");
    /*
     * Skidmap 会将系统的 pam_unix.so 替换为恶意版本，使其接受任意密码，
     * 从而为攻击者提供免密码远程登录能力。
     * 检测方法：检查文件大小与近期修改时间，异常大小或近期修改均视为可疑。
     */
    static const char * const pam_paths[] = {
        "/lib/security/pam_unix.so",
        "/lib64/security/pam_unix.so",
        "/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/usr/lib/security/pam_unix.so",
        NULL
    };
    bool pam_checked = false;
    for (int i = 0; pam_paths[i]; i++) {
        struct stat st;
        if (stat(pam_paths[i], &st) != 0)
            continue;

        pam_checked = true;
        time_t now       = time(NULL);
        double age_hours = difftime(now, st.st_mtime) / 3600.0;

        /* Skidmap 的伪造 pam_unix.so 通常非常小（<50KB），而真实的通常 >80KB */
        bool size_suspicious = (st.st_size < 51200);  /* < 50 KB */
        bool mtime_recent    = (age_hours < 48.0);    /* 48 小时内被修改 */

        if (size_suspicious) {
            alert("  PAM: %s 文件大小异常小 (%lld 字节 < 50KB)"
                  " — 疑似被 Skidmap 替换！",
                  pam_paths[i], (long long)st.st_size);
            FINDING();
        } else if (mtime_recent) {
            warn("  PAM: %s 在 %.1f 小时前被修改 — 请确认是否为正常系统更新",
                 pam_paths[i], age_hours);
        } else {
            ok("  PAM: %s 大小=%lldB  修改于 %.0f 小时前（正常）",
               pam_paths[i], (long long)st.st_size, age_hours);
        }
        break;
    }
    if (!pam_checked)
        warn("  未找到 pam_unix.so（非标准安装路径或未安装 PAM？）");

    /* ── 4. 可疑 cron 持久化检测 ─────────────────────────────────────────── */
    printf("\n  [4] Skidmap cron 持久化检测\n");
    /*
     * Skidmap 通常在系统 cron 目录中写入脚本以实现持久化，
     * 在已隐藏文件的情况下 getdents64 hook 会让这些文件从 ls/find 中消失，
     * 但通过 /proc/kcore 或直接读取 cron spool 仍可发现。
     * 这里检查已知的 Skidmap cron 路径是否存在。
     */
    static const char * const cron_paths[] = {
        "/etc/cron.d/kbuild",
        "/etc/cron.d/iproute",
        "/etc/cron.d/netlink",
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",
        NULL
    };
    int cron_suspicious = 0;
    for (int i = 0; cron_paths[i]; i++) {
        struct stat st;
        if (stat(cron_paths[i], &st) != 0)
            continue;
        /* /var/spool/cron/root 本身存在很正常，只检查 /etc/cron.d/ 下的 Skidmap 特征名 */
        if (strncmp(cron_paths[i], "/etc/cron.d/", 12) == 0) {
            alert("  CRON: 发现 Skidmap 特征 cron 文件: %s", cron_paths[i]);
            FINDING();
            cron_suspicious++;
        }
    }
    if (cron_suspicious == 0)
        ok("  未发现 Skidmap 特征 cron 文件");
}

/* ─── 主函数 ─────────────────────────────────────────────────────────────── */
int main(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "错误: 需要 root 权限\n");
        return 2;
    }

    struct utsname uts;
    uname(&uts);

    printf("\n" C_BLU "╔══════════════════════════════════════════╗\n"
                      "║      ModScan Kcore Deep Scanner          ║\n"
                      "╚══════════════════════════════════════════╝" C_RST "\n");
    printf("  内核版本: %s\n\n", uts.release);

    /* 初始化 kallsyms */
    info("加载 /proc/kallsyms 符号表...");
    if (!parse_kallsyms()) {
        fprintf(stderr, "无法读取 kallsyms\n");
        return 2;
    }
    printf("    已加载 %d 个符号\n\n", ksym_count);

    /* 初始化 kcore */
    info("打开 /proc/kcore...");
    if (!kcore_open()) {
        /* kcore 不可用时，仍可做部分检测 */
        warn("  /proc/kcore 不可用，部分检测将跳过");
        warn("  确保: root 权限, CONFIG_PROC_KCORE=y");
    } else {
        printf("    已解析 %d 个内存段\n\n", nksegs);
    }

    /* 执行所有检测 */
    check_modules_disabled();  printf("\n");
    check_hidden_modules();    printf("\n");

    if (kcore_fd >= 0) {
        check_function_integrity(); printf("\n");
        check_syscall_table();      printf("\n");
    }

    check_skidmap_indicators(); printf("\n");

    /* 总结 */
    printf(C_BLU "────────────────────────────────────────────\n" C_RST);
    if (g_findings == 0) {
        ok("结论: 未发现异常（共 0 项告警）");
        return 0;
    } else {
        alert("结论: 发现 %d 项异常（含 Skidmap 特征），详见上方 [ALERT] 行", g_findings);
        printf("\n" C_YEL "还原建议:" C_RST "\n");
        printf("  方案A: 若 modscan.ko 已预加载\n");
        printf("    echo 'restore <模块名>' > /proc/modscan\n\n");
        printf("  方案B: 使用 kexec（不需要加载模块）\n");
        printf("    kexec -l /boot/vmlinuz --initrd=/boot/initramfs.img --reuse-cmdline\n");
        printf("    kexec -e\n\n");
        printf("  方案C: kdb 调试器（若 CONFIG_KDB=y）\n");
        printf("    echo g > /proc/sysrq-trigger\n");
        printf("    kdb> lsmod && mm <list.next ptr> <value>\n\n");
        printf("  方案D: 从可信介质重启\n");
        return 1;
    }
}
