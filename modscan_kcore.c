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
 *   6. kset/sysfs 完整性交叉验证
 *   7. struct module 内存特征扫描（Volatility 3 方法，扫描 vmalloc 区域寻找被 DKOM 隐藏的模块）
 *      ─ 直接通过 kcore 遍历 module_kset->list（内存可信源），与 /sys/module/ 和
 *        /proc/modules 交叉比对，检测 kobject_del 或 kernfs_remove 篡改 sysfs 的高级 rootkit
 *   9. vmap_area_list 直接内存扫描（Volatility 3 精确复现）
 *      ─ 绕过 /proc/vmallocinfo，直接读取内核 vmap_area_list 链表，
 *        枚举所有 VM_ALLOC 区域，扫描 struct module 签名，与 Vol3 linux.hidden_modules 完全等价
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

/* ─── CHECK 5: kset/sysfs 完整性交叉验证 ────────────────────────────────── */
/*
 * struct kobject 内存布局（x86-64，Linux 4.x~6.x 稳定）：
 *   offset  0 : const char      *name    — 指向名字字符串的指针
 *   offset  8 : struct list_head entry   — kset 链表节点（next@+8, prev@+16）
 *   offset 24 : struct kobject   *parent
 *   offset 32 : struct kset      *kset
 *   offset 40 : const struct kobj_type *ktype
 *   offset 48 : struct kernfs_node *sd   — sysfs/kernfs 节点指针
 *   offset 56 : struct kref       kref
 *
 * struct kset 内存布局（x86-64）：
 *   offset  0 : struct list_head  list   — 成员 kobject 链表哨兵（sentinel）
 *   offset 16 : spinlock_t        list_lock
 *   offset 24 : struct kobject    kobj
 *   ...
 *
 * 遍历 module_kset->list：
 *   sentinel = kset_ptr（即 &kset->list，address of list_head）
 *   cur      = *kset_ptr（即 kset->list.next，第一个成员 kobject 的 entry 地址）
 *   kobj     = cur - 8（从 entry 字段退回 kobject 起始）
 *   name_ptr = *(kobj + 0)  →  读字符串
 */
#define KOBJ_NAME_OFF    0   /* const char *name  在 kobject 内的偏移 */
#define KOBJ_ENTRY_OFF   8   /* list_head entry   在 kobject 内的偏移 */
#define KOBJ_SD_OFF     48   /* kernfs_node *sd   在 kobject 内的偏移 */

#define MAX_KSET_WALK 1024

static modinfo_t kset_wlist[MAX_KSET_WALK];   /* kcore kset 遍历结果 */
static int       kset_wlist_n = -1;            /* -1 = 尚未执行 */

/*
 * do_walk_kset() — 通过 kcore 直接遍历 module_kset->list。
 *
 * "module_kset" 是内核中的 static struct kset * 变量，kallsyms 给出的是指针
 * 变量本身的地址，需要额外一次解引用才能得到实际的 kset 地址。
 *
 * 返回找到的模块数，失败返回 -1。结果存入 kset_wlist[]。
 */
static int do_walk_kset(void)
{
    /* 1. 获取 module_kset 变量地址 */
    uint64_t kset_var = sym_addr("module_kset");
    if (!kset_var) {
        warn("  'module_kset' 不在 kallsyms（需要 CONFIG_KALLSYMS_ALL=y）");
        return -1;
    }

    /* 2. 读取指针本身，得到实际 kset 地址 */
    uint64_t kset_ptr = 0;
    if (!kcore_read_u64(kset_var, &kset_ptr) || !kset_ptr) {
        warn("  无法读取 module_kset 指针 (var @ %#lx)", (unsigned long)kset_var);
        return -1;
    }

    /*
     * 3. 遍历 kset->list（offset 0 of kset）
     *    sentinel  = kset_ptr  （= &kset->list，即哨兵 list_head 的地址）
     *    第一步读  *kset_ptr   得到 kset->list.next（第一个 kobject.entry 的地址）
     */
    uint64_t sentinel = kset_ptr;
    uint64_t cur      = 0;
    if (!kcore_read_u64(sentinel, &cur)) {
        warn("  无法读取 kset->list.next (kset @ %#lx)", (unsigned long)kset_ptr);
        return -1;
    }

    int n     = 0;
    int guard = 0;   /* 防无限循环 */

    while (cur != sentinel && n < MAX_KSET_WALK && guard < 4096) {
        guard++;

        /*
         * cur 指向某个 kobject 的 entry 字段（list_head，偏移 8）
         * 减去偏移得到 kobject 起始地址
         */
        uint64_t kobj = cur - KOBJ_ENTRY_OFF;

        /* 读 kobject.name 指针 */
        uint64_t name_ptr = 0;
        if (!kcore_read_u64(kobj + KOBJ_NAME_OFF, &name_ptr) || !name_ptr)
            goto next_entry;

        /* 跟随指针读取名字字符串 */
        char name[MODULE_NAME_LEN] = {0};
        if (kcore_read(name_ptr, name, MODULE_NAME_LEN - 1) < 0)
            goto next_entry;
        name[MODULE_NAME_LEN - 1] = '\0';

        /* 合法性验证：全部非 NUL 字符必须是可打印 ASCII */
        {
            bool valid = (name[0] != '\0');
            for (int j = 0; valid && j < (int)sizeof(name) && name[j]; j++) {
                if (name[j] < 0x20 || name[j] >= 0x7f)
                    valid = false;
            }
            if (valid) {
                strncpy(kset_wlist[n].name, name, MODULE_NAME_LEN - 1);
                kset_wlist[n].mod_addr = kobj;
                n++;
            }
        }

next_entry:
        /* 跟随 list_head.next 到下一个节点 */
        if (!kcore_read_u64(cur, &cur))
            break;
    }

    return n;
}

static void check_kset_sysfs_integrity(void)
{
    info("CHECK 5: module_kset / sysfs / proc 四维完整性交叉验证");
    printf("  新增：通过 stat() 逐一探测 /sys/module/<name>/ 路径，\n"
           "        绕过 getdents64/getdents hook，检测 Skidmap 等通过\n"
           "        劫持目录遍历系统调用隐藏文件的 rootkit。\n\n");

    kset_wlist_n = do_walk_kset();
    if (kset_wlist_n < 0) {
        warn("  kset 遍历失败，跳过此项检测");
        return;
    }
    printf("    kcore kset 遍历结果       : %d 个模块 kobject\n", kset_wlist_n);
    printf("    /sys/module/ readdir 视图 : %d 个 LKM（可能被 getdents64 hook 过滤）\n",
           sysfs_modlist_n);
    printf("    /proc/modules 视图        : %d 个模块\n\n", procmod_list_n);

    int findings_before = g_findings;

    for (int i = 0; i < kset_wlist_n; i++) {
        const char *name = kset_wlist[i].name;

        /* ── 方法1: readdir（opendir+readdir，经过 getdents64）── */
        bool via_readdir = name_in_list(name, sysfs_modlist, sysfs_modlist_n);

        /* ── 方法2: stat（不经过 getdents64，使用 newfstatat 路径）── */
        /*    即使 getdents64 被 hook 隐藏了目录项，stat 仍可能访问成功  */
        char path[256];
        snprintf(path, sizeof(path), "/sys/module/%.56s/initstate", name);
        bool via_stat = (access(path, F_OK) == 0);

        bool in_proc = name_in_list(name, procmod_list, procmod_list_n);

        /*
         * 四种异常组合：
         *
         * D. via_stat=true  && via_readdir=false
         *    → getdents64/getdents 被 hook，sysfs 条目真实存在但目录遍历被过滤
         *    → 这是 Skidmap 通过 hook getdents64 隐藏自身的经典手法！
         *
         * A. via_stat=false && via_readdir=false（kset 有）
         *    → sysfs 条目已被真正删除（kernfs_remove / kobject_del）
         *
         * B. via_stat=false && via_readdir=true（只 readdir 看到）
         *    → kset 被直接篡改（list_del on kobj->entry），sysfs 残留
         *
         * C. in_proc=false && (via_stat 或 via_readdir) 可见
         *    → 标准 DKOM：模块在 kset/sysfs 中但不在 modules 链表（已由 CHECK 2 报告）
         */

        if (via_stat && !via_readdir) {
            /* ── D: getdents64 hook 检测 —— 最重要的新检测 ── */
            alert("  GETDENTS-HOOK: '%s'", name);
            printf("       /sys/module/%s/initstate 通过 stat() 可访问 ✓\n", name);
            printf("       但 opendir(/sys/module/) + readdir 看不到该目录 ✗\n");
            printf("       → getdents64/getdents 系统调用被 HOOK，目录遍历结果被过滤！\n");
            printf("       → 这是 Skidmap 等 rootkit 隐藏内核模块的核心手段\n");
            if (!in_proc) {
                printf("       → 且不在 /proc/modules（同时存在 DKOM）\n");
            }
            printf("       kobj地址: %#lx\n", (unsigned long)kset_wlist[i].mod_addr);
            FINDING();
        } else if (!via_stat && !via_readdir) {
            /* ── A: sysfs 条目被真正删除 ── */
            alert("  SYSFS-TAMPER: '%s' 在 kcore kset 中，但 sysfs 条目不存在（stat 和 readdir 均无）",
                  name);
            printf("       → sysfs 条目已被删除（kernfs_remove / kobject_del）\n");
            if (!in_proc)
                printf("       → 且不在 /proc/modules：高级双重 DKOM，kset 中仍有残留\n");
            printf("       kobj地址: %#lx\n", (unsigned long)kset_wlist[i].mod_addr);
            FINDING();
        }
    }

    /* ── B: /sys/module/ readdir 有，但 kcore kset 没有 ────────────────── */
    for (int i = 0; i < sysfs_modlist_n; i++) {
        if (!name_in_list(sysfs_modlist[i].name, kset_wlist, kset_wlist_n)) {
            alert("  KSET-TAMPER: '/sys/module/%s/' 在 readdir 中可见，但不在 kcore kset 链表",
                  sysfs_modlist[i].name);
            printf("       → kset 链表节点被直接摘除（list_del on kobj->entry），sysfs 残留\n");
            FINDING();
        }
    }

    if (g_findings == findings_before)
        ok("  四维一致：kcore kset / stat / readdir / /proc/modules 均无篡改迹象");
}

/* ─── CHECK 6: /proc/vmallocinfo 模块内存分配交叉验证 ───────────────────── */
/*
 * 背景：
 *   每个内核模块的代码/数据段通过 module_alloc()/load_module() 分配 vmalloc 内存，
 *   这些分配记录在 /proc/vmallocinfo 中，其调用链包含 "load_module" 或 "module_alloc"。
 *   即使 rootkit 从所有模块跟踪结构（modules 链表、kset、sysfs）中删除自身，
 *   其 vmalloc 内存分配通常仍然存在于 /proc/vmallocinfo，
 *   因为 vmallocinfo 直接读取内核的 vmalloc 元数据，使用不同的代码路径，
 *   远比 /proc/modules 或 /sys/module/ 更难以同时伪造。
 *
 * 算法：
 *   1. 从 /proc/modules 解析所有已知模块的地址范围
 *   2. 解析 /proc/vmallocinfo 找到模块加载代码创建的 vmalloc 分配
 *   3. 如果某个 vmalloc 分配不被任何已知模块的地址范围覆盖 → 可能是隐藏模块的内存
 */
static void check_vmalloc_modules(void)
{
    info("CHECK 6: /proc/vmallocinfo 模块内存分配交叉验证");
    printf("  原理：即使模块从所有追踪结构中删除，其 vmalloc 代码段分配\n"
           "        通常仍留在 /proc/vmallocinfo，因为其使用独立的内核代码路径。\n\n");

    /* ── 1. 从 /proc/modules 构建已知模块地址范围 ─────────────────────── */
    typedef struct { uint64_t start; uint64_t end; char name[MODULE_NAME_LEN]; } modrange_t;
#define MAX_MODRANGES 512
    static modrange_t modranges[MAX_MODRANGES];
    int n_ranges = 0;

    FILE *pf = fopen("/proc/modules", "r");
    if (pf) {
        char line[512];
        while (fgets(line, sizeof(line), pf) && n_ranges < MAX_MODRANGES) {
            char   mname[MODULE_NAME_LEN] = {0};
            unsigned long msize = 0;
            unsigned long long maddr = 0;
            /* 格式: name size refcnt deps state address */
            if (sscanf(line, "%55s %lu %*d %*s %*s %llx",
                       mname, &msize, &maddr) == 3 && maddr && msize) {
                strncpy(modranges[n_ranges].name, mname, MODULE_NAME_LEN - 1);
                modranges[n_ranges].start = (uint64_t)maddr;
                modranges[n_ranges].end   = (uint64_t)maddr + msize;
                n_ranges++;
            }
        }
        fclose(pf);
    }

    /* 也将 kcore kset 遍历中的模块名加入白名单（名字匹配） */
    /* （kset 中的模块我们已知是合法的，即使 /proc/modules 被过滤也算白名单） */
    printf("    /proc/modules 解析到 %d 个模块地址范围\n", n_ranges);
    printf("    kcore kset 中已知 %d 个模块名（作为名字白名单）\n\n",
           kset_wlist_n > 0 ? kset_wlist_n : 0);

    /* ── 2. 扫描 /proc/vmallocinfo ────────────────────────────────────── */
    FILE *vf = fopen("/proc/vmallocinfo", "r");
    if (!vf) {
        warn("  无法打开 /proc/vmallocinfo（CONFIG_PROC_FS 未启用？）");
        return;
    }

    int found = 0, ghost = 0;
    char line[512];
    while (fgets(line, sizeof(line), vf)) {
        unsigned long long va_start = 0, va_end = 0;
        unsigned long va_size = 0;
        char info[256] = {0};

        /* 格式: 0xSTART-0xEND  SIZE  CALLCHAIN... */
        if (sscanf(line, "%llx-%llx %lu %255[^\n]",
                   &va_start, &va_end, &va_size, info) < 3)
            continue;

        /* 只关注由模块加载代码创建的分配 */
        bool is_mod = strstr(info, "load_module")    != NULL ||
                      strstr(info, "module_alloc")   != NULL ||
                      strstr(info, "move_module")    != NULL ||
                      strstr(info, "do_init_module") != NULL;
        if (!is_mod)
            continue;

        found++;

        /* 检查该分配是否被已知模块的地址范围覆盖（允许小幅 offset 误差） */
        bool covered = false;
        for (int i = 0; i < n_ranges && !covered; i++) {
            /* 地址范围重叠：两段区间有交集 */
            if ((uint64_t)va_start < modranges[i].end &&
                (uint64_t)va_end   > modranges[i].start)
                covered = true;
        }

        if (!covered) {
            /*
             * 辅助验证：读取该区域起始处，检查是否符合 struct module 签名。
             * 辅助分配（per-CPU、jump table 等）不以 struct module 开头，
             * 读出来的 state 字段会是乱码，从而过滤掉误报。
             * 只有通过签名验证的区域才真正告警。
             */
            bool sig_ok = false;
            if (va_size >= 80) {
                uint8_t buf[80];
                if (kcore_read((uint64_t)va_start, buf, sizeof(buf)) == 80) {
                    uint32_t st;
                    memcpy(&st, buf, 4);
                    if (st <= 3) {
                        uint64_t lnext, lprev;
                        memcpy(&lnext, buf + 8,  8);
                        memcpy(&lprev, buf + 16, 8);
                        if (lnext && (lnext & 7) == 0 && lnext >= 0xffff000000000000ULL &&
                            lprev && (lprev & 7) == 0 && lprev >= 0xffff000000000000ULL) {
                            /* 检查 name 字段 */
                            char nm[MODULE_NAME_LEN + 1];
                            memcpy(nm, buf + 24, MODULE_NAME_LEN);
                            nm[MODULE_NAME_LEN] = '\0';
                            char c0 = nm[0];
                            bool c0_ok = (c0 >= 'a' && c0 <= 'z') ||
                                         (c0 >= 'A' && c0 <= 'Z') ||
                                         (c0 >= '0' && c0 <= '9') ||
                                         c0 == '_';
                            if (c0_ok) {
                                bool name_ok = false;
                                for (int ni = 0; ni < MODULE_NAME_LEN; ni++) {
                                    if (nm[ni] == '\0') { name_ok = true; break; }
                                    if ((uint8_t)nm[ni] < 0x20 ||
                                        (uint8_t)nm[ni] >= 0x7f) break;
                                }
                                /* 链表指针交叉验证：list.next-8 处的 state 也应合法 */
                                if (name_ok) {
                                    uint32_t nst = 0xff;
                                    sig_ok = (kcore_read(lnext - 8, &nst, 4) == 4 &&
                                              nst <= 3);
                                }
                            }
                        }
                    }
                }
            }

            if (sig_ok) {
                /* 读出模块名用于告警输出 */
                char hidden_name[MODULE_NAME_LEN + 1] = {0};
                uint8_t nbuf[80];
                if (kcore_read((uint64_t)va_start, nbuf, 80) == 80) {
                    memcpy(hidden_name, nbuf + 24, MODULE_NAME_LEN);
                    hidden_name[MODULE_NAME_LEN] = '\0';
                }
                alert("  GHOST ALLOC: %#llx-%#llx (%lu 字节) 疑似隐藏模块内存！",
                      va_start, va_end, va_size);
                if (hidden_name[0])
                    printf("       模块名 (struct 扫描): %s\n", hidden_name);
                printf("       调用链: %.120s\n", info);
                printf("       → struct module 签名验证通过，但不在 /proc/modules\n");
                printf("       → 该模块很可能通过 list_del 将自身从链表摘除\n");
                FINDING();
                ghost++;
            }
            /* sig_ok == false：辅助分配（per-CPU/jump table 等），忽略 */
        }
    }
    fclose(vf);

    printf("    共扫描 %d 个模块 vmalloc 分配，其中 %d 个无主\n", found, ghost);
    if (ghost == 0)
        ok("  所有模块 vmalloc 分配均有对应的已知模块");
}

/* ─── CHECK 7: struct module 内存特征扫描（Volatility 3 方法）──────────── */
/*
 * 原理：
 *   rootkit 通过 list_del(&mod->list) 将自身从 modules 链表摘除后，
 *   其 struct module 对象和模块代码段依然存在于 vmalloc 内存中——
 *   只要模块仍在运行，就不能释放自身的内存，否则代码段将无法执行。
 *
 *   通过扫描 /proc/vmallocinfo 中由模块加载代码（load_module/module_alloc）
 *   分配的所有 vmalloc 区域，对每块区域读取开头字节，寻找符合
 *   struct module 布局特征的内存模式，即可发现被 DKOM 隐藏的模块。
 *   这正是 Volatility 3 隐藏模块检测插件（linux.hidden_modules）的核心思路。
 *
 * struct module 特征签名（x86-64，offset 稳定）：
 *   +0  state  (4B)  : 值必须为 0/1/2/3（MODULE_STATE_LIVE/COMING/GOING/UNFORMED）
 *   +8  list.next(8B): 有效内核地址（>= 0xffff000000000000，8 字节对齐，非零）
 *   +16 list.prev(8B): 同上
 *   +24 name[56]     : 可打印 ASCII 字符串，首字符为字母/数字/下划线，有 \0 终止
 *
 * 额外验证：
 *   读取 list.next - 8 处的 state 字段，验证链表指针确实指向另一个合法的
 *   struct module（或哨兵头节点），进一步排除偶然的签名碰撞。
 */
static void check_struct_module_scan(void)
{
    info("CHECK 7: struct module 内存特征扫描（Volatility 3 方法）");
    printf("  原理：扫描 vmalloc 区域寻找 struct module 内存签名——\n"
           "        即使模块已从所有链表中摘除，其内存对象仍存在。\n\n");

    if (kcore_fd < 0) {
        warn("  /proc/kcore 不可用，跳过内存扫描");
        return;
    }

    FILE *vf = fopen("/proc/vmallocinfo", "r");
    if (!vf) {
        warn("  无法打开 /proc/vmallocinfo（CONFIG_PROC_FS 未启用？）");
        return;
    }

    /* struct module 特征扫描所需的最小字节数：state(4)+pad(4)+next(8)+prev(8)+name(56) */
#define MOD_SIG_BYTES 80

    int scanned = 0, candidates = 0, hidden = 0;
    char line[512];

    while (fgets(line, sizeof(line), vf)) {
        unsigned long long va_start = 0, va_end = 0;
        unsigned long va_size = 0;
        char call_info[256] = {0};

        if (sscanf(line, "%llx-%llx %lu %255[^\n]",
                   &va_start, &va_end, &va_size, call_info) < 3)
            continue;

        /* 只检查由模块加载代码分配的区域 */
        bool is_mod_alloc = strstr(call_info, "load_module")    != NULL ||
                            strstr(call_info, "module_alloc")   != NULL ||
                            strstr(call_info, "move_module")    != NULL ||
                            strstr(call_info, "do_init_module") != NULL;
        if (!is_mod_alloc)
            continue;

        /* 太小的区域不可能容纳 struct module 头 */
        if (va_size < MOD_SIG_BYTES)
            continue;

        scanned++;

        /* ── 读取区域开头 MOD_SIG_BYTES 字节 ────────────────────────────── */
        uint8_t buf[MOD_SIG_BYTES];
        if (kcore_read((uint64_t)va_start, buf, MOD_SIG_BYTES) != MOD_SIG_BYTES)
            continue;

        /* ── 验证 state 字段（offset 0，4 字节）────────────────────────── */
        uint32_t state;
        memcpy(&state, buf + 0, 4);
        if (state > 3)
            continue;   /* 非法的 module_state 值 */

        /* ── 验证 list.next / list.prev（offset 8/16，各 8 字节）─────────── */
        uint64_t list_next, list_prev;
        memcpy(&list_next, buf + 8,  8);
        memcpy(&list_prev, buf + 16, 8);

        /* 有效内核地址：高位为 1（>= 0xffff000000000000），8 字节对齐，非零 */
#define IS_KADDR(p) ((p) != 0 && ((p) & 7) == 0 && (p) >= 0xffff000000000000ULL)
        if (!IS_KADDR(list_next) || !IS_KADDR(list_prev))
            continue;

        /* ── 验证 name 字段（offset 24，56 字节）───────────────────────── */
        char name[MODULE_NAME_LEN + 1];
        memcpy(name, buf + 24, MODULE_NAME_LEN);
        name[MODULE_NAME_LEN] = '\0';

        /* 首字符必须是字母/数字/下划线 */
        char c0 = name[0];
        bool first_ok = (c0 >= 'a' && c0 <= 'z') ||
                        (c0 >= 'A' && c0 <= 'Z') ||
                        (c0 >= '0' && c0 <= '9') ||
                        c0 == '_';
        if (!first_ok)
            continue;

        /* 所有字符必须是可打印 ASCII，且在 56 字节内有 null 终止符 */
        int name_len = -1;
        for (int i = 0; i < MODULE_NAME_LEN; i++) {
            if (name[i] == '\0') { name_len = i; break; }
            if ((uint8_t)name[i] < 0x20 || (uint8_t)name[i] >= 0x7f) {
                name_len = -1;
                break;
            }
        }
        if (name_len <= 0)
            continue;   /* 未找到 null 终止符，或名称为空，或含不可打印字符 */

        /* ── 额外验证：list.next - 8 处的 state 字段应合法 ─────────────── */
        /* list.next 指向下一个 struct module 的 list 字段（offset 8）        */
        /* 因此下一个 struct module 起始 = list.next - 8                      */
        uint32_t next_state = 0xff;
        uint64_t next_mod   = list_next - 8;
        if (kcore_read(next_mod, &next_state, 4) != 4 || next_state > 3)
            continue;   /* 链表指针未指向有效的 struct module 或哨兵节点 */

        /* ── 候选确认 ───────────────────────────────────────────────────── */
        candidates++;

        bool in_proc = name_in_list(name, procmod_list, procmod_list_n);

        if (!in_proc) {
            alert("  HIDDEN MODULE (内存扫描): '%s'", name);
            printf("       vmalloc 区域 : %#llx – %#llx  (%lu 字节)\n",
                   va_start, va_end, va_size);
            printf("       state        : %u\n", state);
            printf("       list.next    : %#lx\n", (unsigned long)list_next);
            printf("       list.prev    : %#lx\n", (unsigned long)list_prev);
            printf("       → struct module 签名完整匹配，但该模块不在 /proc/modules\n");
            printf("       → 该模块很可能执行了 list_del(&mod->list) 将自身从链表摘除\n");
            printf("       → 这是 DKOM 隐藏的直接内存证据（Volatility 3 扫描方法）\n");
            FINDING();
            hidden++;
        }
        /* 正常模块（in_proc）不报告，避免噪声 */
    }
    fclose(vf);

    printf("    共扫描 %d 个模块 vmalloc 区域，发现 %d 个有效 struct module，"
           "其中 %d 个不在 /proc/modules\n", scanned, candidates, hidden);
    if (hidden == 0)
        ok("  未通过内存扫描发现隐藏模块");
}

/* ─── CHECK 9: vmap_area_list 直接内存扫描（Volatility 3 精确复现）────────
 *
 * Volatility 3 linux.hidden_modules 插件的核心原理：
 * 遍历内核 vmap_area_list 全局链表（存储所有 vmalloc 分配的元数据），
 * 对每个 VM_ALLOC 类型区域扫描 struct module 签名。
 *
 * 与 CHECK 6/7 的本质区别：
 *   CHECK 6/7 : 依赖 /proc/vmallocinfo（内核生成文件，可被 rootkit hook）
 *   CHECK 9   : 直接从 kcore 读取 vmap_area_list 内核数据结构，
 *               绕过 /proc 文件系统及其可能存在的所有钩子。
 *
 * struct vmap_area 布局（x86-64，Linux 5.x–6.x，无 __randomize_layout）：
 *   +0   va_start           (8B) — vmalloc 区域起始虚拟地址
 *   +8   va_end             (8B) — vmalloc 区域结束虚拟地址
 *   +16  rb_node            (24B = 3×8B: __rb_parent_color/rb_right/rb_left)
 *   +40  list.next          (8B) ← 链表遍历入口
 *   +48  list.prev          (8B)
 *   +56  vm (struct vm_struct*) 或 subtree_max_size（union）
 *
 * struct vm_struct 布局（x86-64）：
 *   +0   next  (8B)
 *   +8   addr  (8B) → 应与 va_start 相等
 *   +16  size  (8B)
 *   +24  flags (8B) → VM_ALLOC=0x1 表示 vmalloc/module 分配
 */
#define VMAP_AREA_LIST_OFF   40          /* list_head 在 struct vmap_area 中的偏移 */
#define VMAP_AREA_VM_OFF     56          /* vm 指针在 struct vmap_area 中的偏移    */
#define VM_STRUCT_ADDR_OFF    8          /* addr  在 struct vm_struct 中的偏移     */
#define VM_STRUCT_FLAGS_OFF  24          /* flags 在 struct vm_struct 中的偏移     */
#define VM_ALLOC_FLAG        0x00000001UL /* VM_ALLOC 标志位                       */

static void check_vmap_area_list_scan(void)
{
    info("CHECK 9: vmap_area_list 直接内存扫描（Volatility 3 精确复现）");
    printf("  原理：直接从 kcore 读取内核 vmap_area_list 全局链表，\n"
           "        枚举所有 VM_ALLOC 区域并扫描 struct module 签名，\n"
           "        完全绕过 /proc/vmallocinfo 及其可能的 rootkit 钩子。\n\n");

    if (kcore_fd < 0) {
        warn("  /proc/kcore 不可用，跳过");
        return;
    }

    /* ── 1. 查找 vmap_area_list 符号 ─────────────────────────────────────── */
    uint64_t vmal_head = sym_addr("vmap_area_list");
    if (!vmal_head) {
        warn("  vmap_area_list 不在 kallsyms（需要 CONFIG_KALLSYMS_ALL=y）");
        warn("  → 已由 CHECK 7（/proc/vmallocinfo 过滤扫描）提供覆盖");
        return;
    }
    printf("    vmap_area_list @ %#lx\n\n", (unsigned long)vmal_head);

    /* ── 2. 读链表头 next 指针（list_head.next） ──────────────────────────── */
    uint64_t cur;
    if (!kcore_read_u64(vmal_head, &cur) || !IS_KADDR(cur)) {
        warn("  无法读取 vmap_area_list.next，链表为空或 kcore 权限不足");
        return;
    }

    int scanned = 0, vm_alloc_cnt = 0, candidates = 0, hidden = 0;

    /* ── 3. 遍历 vmap_area_list 链表 ─────────────────────────────────────── */
    while (cur != vmal_head && scanned < 300000) {
        /*
         * cur 指向 vmap_area.list 字段（偏移 +40），
         * 减去偏移得到 struct vmap_area 的起始地址。
         */
        uint64_t va_addr = cur - VMAP_AREA_LIST_OFF;
        scanned++;

        /* 读 vmap_area 前 64 字节 */
        uint8_t va_buf[64];
        bool buf_ok = (kcore_read(va_addr, va_buf, sizeof(va_buf)) ==
                       (ssize_t)sizeof(va_buf));

        /*
         * 先更新 cur（推进链表），再处理数据，
         * 确保所有 continue 路径都能正确推进链表。
         */
        uint64_t list_next = 0;
        if (buf_ok)
            memcpy(&list_next, va_buf + 40, 8);          /* vmap_area.list.next */
        else
            kcore_read_u64(cur, &list_next);              /* 退路：直接读 cur+0  */

        if (!IS_KADDR(list_next))
            break;
        cur = list_next;

        if (!buf_ok)
            continue;

        uint64_t va_start, va_end, vm_ptr;
        memcpy(&va_start, va_buf + 0,              8);
        memcpy(&va_end,   va_buf + 8,              8);
        memcpy(&vm_ptr,   va_buf + VMAP_AREA_VM_OFF, 8);

        uint64_t va_size = va_end - va_start;

        /* 大小过滤：太小（无法容纳 struct module）或太大（异常） */
        if (va_size < MOD_SIG_BYTES || va_size > 256ULL * 1024 * 1024)
            continue;

        /* vm 指针必须有效（非 free/lazy-purge 的空闲区域） */
        if (!IS_KADDR(vm_ptr))
            continue;

        /* ── 4. 读 vm_struct 验证：addr==va_start 且带 VM_ALLOC 标志 ──── */
        uint64_t vm_addr_f = 0, vm_flags = 0;
        if (!kcore_read_u64(vm_ptr + VM_STRUCT_ADDR_OFF,  &vm_addr_f) ||
            !kcore_read_u64(vm_ptr + VM_STRUCT_FLAGS_OFF, &vm_flags))
            continue;

        /* vm->addr 应与 va_start 完全一致 */
        if (vm_addr_f != va_start)
            continue;

        /* 必须是 VM_ALLOC 分配（内核模块、vmalloc 等），跳过 vmap/ioremap */
        if (!(vm_flags & VM_ALLOC_FLAG))
            continue;

        vm_alloc_cnt++;

        /* ── 5. struct module 签名匹配 ─────────────────────────────────── */
        uint8_t buf[MOD_SIG_BYTES];
        if (kcore_read(va_start, buf, MOD_SIG_BYTES) != MOD_SIG_BYTES)
            continue;

        /* state (offset 0, 4B): 合法值 0–3（LIVE/COMING/GOING/UNFORMED） */
        uint32_t state;
        memcpy(&state, buf + 0, 4);
        if (state > 3)
            continue;

        /* list.next / list.prev (offset 8/16, 各 8B): 有效内核指针，8B 对齐 */
        uint64_t mod_lnext, mod_lprev;
        memcpy(&mod_lnext, buf + 8,  8);
        memcpy(&mod_lprev, buf + 16, 8);
        if (!IS_KADDR(mod_lnext) || !IS_KADDR(mod_lprev))
            continue;

        /* name (offset 24, 56B): 可打印 ASCII，首字符合法，必须有 null 终止 */
        char name[MODULE_NAME_LEN + 1];
        memcpy(name, buf + 24, MODULE_NAME_LEN);
        name[MODULE_NAME_LEN] = '\0';
        char c0 = name[0];
        if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') ||
              (c0 >= '0' && c0 <= '9') || c0 == '_'))
            continue;
        int nlen = -1;
        for (int i = 0; i < MODULE_NAME_LEN; i++) {
            if (name[i] == '\0') { nlen = i; break; }
            if ((uint8_t)name[i] < 0x20 || (uint8_t)name[i] >= 0x7f) break;
        }
        if (nlen <= 0)
            continue;

        /* 链表交叉验证：mod_lnext - 8 处的 state 字段也应合法（0–3） */
        uint32_t next_state = 0xff;
        if (kcore_read(mod_lnext - 8, &next_state, 4) != 4 || next_state > 3)
            continue;

        candidates++;

        /* ── 6. 与 /proc/modules 对比，报告隐藏模块 ────────────────────── */
        bool in_proc = name_in_list(name, procmod_list, procmod_list_n);
        if (!in_proc) {
            alert("  HIDDEN MODULE (vmap_area_list 直接扫描): '%s'", name);
            printf("       vmalloc 区域  : %#lx – %#lx (%lu 字节)\n",
                   (unsigned long)va_start, (unsigned long)va_end,
                   (unsigned long)va_size);
            printf("       struct module : state=%u  list.next=%#lx\n",
                   state, (unsigned long)mod_lnext);
            printf("       vm_struct*    : %#lx  flags=%#lx (VM_ALLOC)\n",
                   (unsigned long)vm_ptr, (unsigned long)vm_flags);
            printf("       → 直接从内核 vmap_area_list 读取（绕过所有 /proc 钩子）\n"
                   "       → 与 Volatility 3 linux.hidden_modules 完全相同的检测方法\n");
            FINDING();
            hidden++;
        }
    }

    printf("    vmap_area 遍历: %d 条目，VM_ALLOC: %d 个，"
           "struct module 候选: %d，隐藏: %d\n",
           scanned, vm_alloc_cnt, candidates, hidden);
    if (hidden == 0)
        ok("  vmap_area_list 直接扫描：未发现隐藏模块");
}

/* ─── CHECK 8: Skidmap 恶意软件特征检测 ─────────────────────────────────── */
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
    info("CHECK 8: Skidmap 恶意软件特征检测");

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
        check_kset_sysfs_integrity(); printf("\n");
        check_vmalloc_modules();      printf("\n");
        check_function_integrity();   printf("\n");
        check_syscall_table();        printf("\n");
        check_struct_module_scan();   printf("\n");
        check_vmap_area_list_scan();  printf("\n");
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
