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
 *   3. finit_module / init_module / load_module 内联 patch
 *   4. 系统调用表指针劫持 (sys_call_table[313])
 *   5. struct module 内存特征扫描（不依赖链表）
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

#define MAX_MODULES 1024

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

typedef struct {
    char name[MODULE_NAME_LEN];
    int  sym_count;
} ksym_modref_t;

static ksym_modref_t ksym_modrefs[MAX_MODULES];
static int           ksym_modrefs_n;

static void set_mod_name(char dst[MODULE_NAME_LEN], const char *src)
{
    size_t n = strnlen(src, MODULE_NAME_LEN - 1);

    memcpy(dst, src, n);
    dst[n] = '\0';
}

static void add_ksym_modref(const char *name)
{
    for (int i = 0; i < ksym_modrefs_n; i++) {
        if (strcmp(ksym_modrefs[i].name, name) == 0) {
            ksym_modrefs[i].sym_count++;
            return;
        }
    }

    if (ksym_modrefs_n >= MAX_MODULES)
        return;

    set_mod_name(ksym_modrefs[ksym_modrefs_n].name, name);
    ksym_modrefs[ksym_modrefs_n].sym_count = 1;
    ksym_modrefs_n++;
}

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
        char     type[4], name[128], modtag[MODULE_NAME_LEN + 4] = {0};
        int      fields;

        fields = sscanf(line, "%lx %3s %127s %59s", &addr, type, name, modtag);
        if (fields < 3)
            continue;
        if (addr == 0)
            continue;

        ksym_entry_t *e = &ksym_pool[ksym_count++];
        e->name = strdup(name);
        e->addr = addr;

        uint32_t h = fnv1a(name) & KSYM_HASH_MASK;
        e->next       = ksym_hash[h];
        ksym_hash[h]  = e;

        if (fields >= 4 && modtag[0] == '[') {
            char *end = strchr(modtag, ']');

            if (end && end > modtag + 1) {
                *end = '\0';
                add_ksym_modref(modtag + 1);
            }
        }
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
            if (fscanf(f, "%d", &val) == 1) {
                if (val == 1) {
                    alert("  modules_disabled=1 — 模块加载已被永久禁止！");
                    FINDING();
                } else {
                    ok("  modules_disabled=0（正常）");
                }
            } else {
                warn("  无法解析 /proc/sys/kernel/modules_disabled");
            }
            fclose(f);
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
        if (fscanf(f, "%d", &val) == 1) {
            if (val == 1) {
                alert("  kexec_load_disabled=1 — kexec 恢复路径被封锁！");
                FINDING();
            } else {
                ok("  kexec_load_disabled=0（kexec 可用）");
            }
        } else {
            warn("  无法解析 /proc/sys/kernel/kexec_load_disabled");
        }
        fclose(f);
    }
}

/* ─── CHECK 2: 走 modules 链表，与 /sys/module/ 对比 ────────────────────── */

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
static bool      module_views_ready;

typedef struct {
    char     name[MODULE_NAME_LEN];
    uint64_t mod_addr;
    int      score;
} carved_mod_t;

static carved_mod_t carved_modlist[MAX_MODULES];
static int          carved_modlist_n;

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

        set_mod_name(kcore_modlist[n].name, name);
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
        set_mod_name(sysfs_modlist[n].name, de->d_name);
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
            set_mod_name(procmod_list[n].name, name);
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

static int ksym_modref_count(const char *name)
{
    for (int i = 0; i < ksym_modrefs_n; i++) {
        if (strcmp(ksym_modrefs[i].name, name) == 0)
            return ksym_modrefs[i].sym_count;
    }
    return 0;
}

static bool is_kernel_ptr(uint64_t p)
{
    return p >= 0xffff000000000000ULL && (p & 0x7) == 0;
}

static bool valid_mod_name_char(char c)
{
    if (c >= 'a' && c <= 'z')
        return true;
    if (c >= 'A' && c <= 'Z')
        return true;
    if (c >= '0' && c <= '9')
        return true;
    return c == '_' || c == '-' || c == '.';
}

static int score_module_blob(const uint8_t *p, char out_name[MODULE_NAME_LEN])
{
    int32_t state = 0;
    uint64_t next = 0, prev = 0;
    const char *name = (const char *)(p + MODULE_NAME_OFF);
    size_t len = 0;
    int score = 0;

    memcpy(&state, p + MODULE_STATE_OFF, sizeof(state));
    memcpy(&next, p + MODULE_LIST_NEXT_OFF, sizeof(next));
    memcpy(&prev, p + MODULE_LIST_PREV_OFF, sizeof(prev));

    while (len < MODULE_NAME_LEN && name[len] != '\0') {
        if (!valid_mod_name_char(name[len]))
            return 0;
        len++;
    }
    if (len < 2 || len >= MODULE_NAME_LEN)
        return 0;

    set_mod_name(out_name, name);
    score++;

    if (state >= 0 && state <= 8)
        score++;
    if (is_kernel_ptr(next))
        score++;
    if (is_kernel_ptr(prev))
        score++;
    if (next != 0 && prev != 0 && next != prev)
        score++;
    if (ksym_modref_count(out_name) > 0)
        score++;

    return score;
}

static void add_carved_candidate(const char *name, uint64_t mod_addr, int score)
{
    for (int i = 0; i < carved_modlist_n; i++) {
        if (strcmp(carved_modlist[i].name, name) == 0) {
            if (score > carved_modlist[i].score) {
                carved_modlist[i].mod_addr = mod_addr;
                carved_modlist[i].score = score;
            }
            return;
        }
        if (carved_modlist[i].mod_addr == mod_addr)
            return;
    }

    if (carved_modlist_n >= MAX_MODULES)
        return;

    set_mod_name(carved_modlist[carved_modlist_n].name, name);
    carved_modlist[carved_modlist_n].mod_addr = mod_addr;
    carved_modlist[carved_modlist_n].score = score;
    carved_modlist_n++;
}

static int carve_module_candidates(void)
{
    enum { CARVE_CHUNK = 1 << 20, CARVE_STEP = 8 };
    const size_t need = MODULE_NAME_OFF + MODULE_NAME_LEN;
    uint8_t *buf;

    carved_modlist_n = 0;
    buf = malloc(CARVE_CHUNK);
    if (!buf)
        return -1;

    for (int s = 0; s < nksegs; s++) {
        uint64_t seg_start = ksegs[s].vaddr;
        uint64_t seg_end = ksegs[s].vaddr + ksegs[s].filesz;
        uint64_t va = seg_start;

        if (seg_end < 0xffff000000000000ULL)
            continue;
        if (seg_start < 0xffff000000000000ULL)
            seg_start = 0xffff000000000000ULL;
        va = seg_start;

        if (ksegs[s].filesz < need)
            continue;

        while (va + need <= seg_end) {
            size_t to_read = CARVE_CHUNK;
            if (va + to_read > seg_end)
                to_read = (size_t)(seg_end - va);

            off_t foff = (off_t)(ksegs[s].file_offset + (va - seg_start));
            ssize_t got = pread(kcore_fd, buf, to_read, foff);
            if (got <= 0)
                break;

            size_t limit = (size_t)got;
            if (limit < need)
                break;

            for (size_t off = 0; off + need <= limit; off += CARVE_STEP) {
                char name[MODULE_NAME_LEN];
                int score = score_module_blob(buf + off, name);

                if (score < 5)
                    continue;
                add_carved_candidate(name, va + off, score);
            }

            va += limit;
        }
    }

    free(buf);
    return carved_modlist_n;
}

static void check_module_carving(void)
{
    info("CHECK 3: struct module 内存特征扫描（不依赖链表）");

    if (kcore_fd < 0 || nksegs <= 0) {
        warn("  /proc/kcore 不可用，跳过内存特征扫描");
        return;
    }

    int n = carve_module_candidates();
    if (n < 0) {
        warn("  内存特征扫描初始化失败");
        return;
    }

    if (!module_views_ready) {
        warn("  依赖视图未就绪（/sys/module 或 /proc/modules 读取失败），仅输出候选数量");
        printf("    carving 命中 %d 个候选模块对象\n", n);
        return;
    }

    printf("    carving 命中 %d 个候选模块对象\n", n);

    int high_risk = 0;
    int confirmed = 0;
    for (int i = 0; i < carved_modlist_n; i++) {
        bool in_kcore = name_in_list(carved_modlist[i].name,
                                     kcore_modlist, kcore_modlist_n);
        bool in_proc  = name_in_list(carved_modlist[i].name,
                                     procmod_list, procmod_list_n);
        bool in_sysfs = name_in_list(carved_modlist[i].name,
                                     sysfs_modlist, sysfs_modlist_n);
        int  ksym_n   = ksym_modref_count(carved_modlist[i].name);

        if (!in_kcore && !in_proc && !in_sysfs) {
            alert("  CARVED_HIDDEN_HIGH: '%s' 仅在内存特征扫描中出现（score=%d, addr=%#lx）",
                  carved_modlist[i].name, carved_modlist[i].score,
                  (unsigned long)carved_modlist[i].mod_addr);
            FINDING();
            high_risk++;
        } else if (!in_proc && in_sysfs) {
            alert("  DKOM_HIDDEN_CONFIRMED: '%s' carving+sysfs 命中，但 /proc/modules 缺失",
                  carved_modlist[i].name);
            FINDING();
            confirmed++;
        } else if (in_proc && !in_sysfs && ksym_n > 0) {
            alert("  KSET_SYSFS_TAMPER_SUSPECT: '%s' carving+/proc/kallsyms 命中，但 /sys/module 缺失",
                  carved_modlist[i].name);
            FINDING();
            confirmed++;
        }
    }

    if (high_risk == 0 && confirmed == 0)
        ok("  carving 与现有视图未发现额外高风险隐藏模块");
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

    if (sysfs_modlist_n < 0 || procmod_list_n < 0) {
        module_views_ready = false;
        return;
    }

    module_views_ready = true;

    printf("    /sys/module/ 共 %d 个 LKM，/proc/modules 共 %d 个模块，kallsyms 模块标签 %d 个\n",
           sysfs_modlist_n, procmod_list_n, ksym_modrefs_n);

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

        /* ── 检测4: kcore/proc 有但 sysfs 无 → 可能 kset/sysfs 被篡改 ── */
        for (int i = 0; i < kcore_modlist_n; i++) {
            bool in_sysfs = name_in_list(kcore_modlist[i].name,
                                         sysfs_modlist, sysfs_modlist_n);
            bool in_proc  = name_in_list(kcore_modlist[i].name,
                                         procmod_list, procmod_list_n);
            if (in_proc && !in_sysfs) {
                alert("  KSET/SYSFS_TAMPER_SUSPECT: '%s' 在 kcore 链表和 /proc/modules 中，但不在 /sys/module/",
                      kcore_modlist[i].name);
                FINDING();
            }
        }
    }

    /* ── 检测5: kallsyms 模块标签与 proc/sysfs 交叉验证 ── */
    for (int i = 0; i < ksym_modrefs_n; i++) {
        bool in_proc  = name_in_list(ksym_modrefs[i].name,
                                     procmod_list, procmod_list_n);
        bool in_sysfs = name_in_list(ksym_modrefs[i].name,
                                     sysfs_modlist, sysfs_modlist_n);

        if (!in_proc && !in_sysfs) {
            alert("  KALLSYMS_ORPHAN: '%s' 仅存在于 kallsyms 标签（%d 个符号），不在 /proc/modules 和 /sys/module/",
                  ksym_modrefs[i].name, ksym_modrefs[i].sym_count);
            FINDING();
        } else if (in_proc && !in_sysfs) {
            alert("  SYSFS_TAMPER_SUSPECT: '%s' 在 /proc/modules 与 kallsyms 中存在，但 /sys/module/ 缺失",
                  ksym_modrefs[i].name);
            FINDING();
        }
    }

    /* ── 检测6: sysfs 独有且 proc/kallsyms 都无 → 可能 sysfs 伪造 ── */
    for (int i = 0; i < sysfs_modlist_n; i++) {
        bool in_proc = name_in_list(sysfs_modlist[i].name,
                                    procmod_list, procmod_list_n);
        int  ksym_n  = ksym_modref_count(sysfs_modlist[i].name);

        if (!in_proc && ksym_n == 0) {
            warn("  SYSFS_INCONSISTENCY: '%s' 仅出现在 /sys/module/，不在 /proc/modules 且无 kallsyms 模块符号",
                 sysfs_modlist[i].name);
            FINDING();
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
    info("CHECK 4: 内核函数内联 patch 检测");

    static const struct {
        const char *symname;
        const char *desc;
    } targets[] = {
        { "__x64_sys_finit_module", "finit_module 系统调用入口" },
        { "__x64_sys_init_module",  "init_module 系统调用入口"  },
        { "load_module",            "核心模块加载函数"           },
        { "security_kernel_post_read_file", "LSM post-read-file hook" },
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
    info("CHECK 5: 系统调用表指针完整性");

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
        { 313, "__x64_sys_finit_module", "finit_module (#313)" },
        { 175, "__x64_sys_init_module",  "init_module  (#175)" },
        { 0,   NULL, NULL }
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
    check_module_carving();    printf("\n");

    if (kcore_fd >= 0) {
        check_function_integrity(); printf("\n");
        check_syscall_table();      printf("\n");
    }

    /* 总结 */
    printf(C_BLU "────────────────────────────────────────────\n" C_RST);
    if (g_findings == 0) {
        ok("结论: 未发现异常（共 0 项告警）");
        return 0;
    } else {
        alert("结论: 发现 %d 项异常，详见上方 [ALERT] 行", g_findings);
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
