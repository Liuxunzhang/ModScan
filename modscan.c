// SPDX-License-Identifier: GPL-2.0
/*
 * modscan.c — DKOM hidden-module detector and restorer
 *
 * Rootkits can hide a kernel module by calling list_del(&mod->list),
 * removing it from the global "modules" linked list that lsmod/rmmod use.
 * The module stays mapped and running, but becomes invisible.
 *
 * This tool detects such modules by comparing two independent kernel
 * data structures:
 *
 *   1. module_kset  — a kset whose kobject list tracks *every* registered
 *                     module, including DKOM-hidden ones.
 *   2. modules list — the linked list that lsmod reads via /proc/modules.
 *
 * Any module present in the kset but absent from the modules list is hidden.
 * The restore command re-inserts it with list_add(), making it visible to
 * lsmod and removable with rmmod again.
 *
 * Interface — /proc/modscan:
 *   read                        → scan and print hidden modules
 *   write "restore <modname>"   → re-link the named module into modules list
 *
 * Supported kernels: 4.x – 6.x
 *   • Uses kprobe to locate kallsyms_lookup_name on kernels ≥ 5.7 where
 *     it is no longer exported.
 *   • Uses proc_ops on kernels ≥ 5.6, file_operations on older kernels.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernfs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# define MODSCAN_KPROBE_KALLSYMS 1
# include <linux/kprobes.h>
#else
# include <linux/kallsyms.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ModScan");
MODULE_DESCRIPTION("DKOM hidden-module detector and restorer");
MODULE_VERSION("1.0");

/* ------------------------------------------------------------------ */
/*  kallsyms_lookup_name resolution                                    */
/* ------------------------------------------------------------------ */

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t modscan_kallsyms;

#ifdef MODSCAN_KPROBE_KALLSYMS
static struct kprobe kp_ksym = {
	.symbol_name = "kallsyms_lookup_name",
};

static int __init resolve_kallsyms(void)
{
	int ret = register_kprobe(&kp_ksym);

	if (ret < 0) {
		pr_err("modscan: register_kprobe failed (%d)\n", ret);
		return ret;
	}
	modscan_kallsyms = (kallsyms_lookup_name_t)kp_ksym.addr;
	unregister_kprobe(&kp_ksym);
	pr_info("modscan: kallsyms_lookup_name @ %px\n", modscan_kallsyms);
	return 0;
}
#else
static int __init resolve_kallsyms(void)
{
	modscan_kallsyms = kallsyms_lookup_name;
	return 0;
}
#endif /* MODSCAN_KPROBE_KALLSYMS */

/* ------------------------------------------------------------------ */
/*  Kernel symbol pointers resolved at init time                       */
/* ------------------------------------------------------------------ */

/*
 * modules_list_head — head of the global "modules" LIST_HEAD.
 * module_kset       — kset whose ->list contains every module's kobject.
 * mod_mutex         — mutex protecting the modules list.
 *
 * module_mutex is GPL-exported so we can reference it directly;
 * the other two are static in the kernel and found via kallsyms.
 */
extern struct mutex module_mutex;

static struct list_head *modules_list_head;
static struct kset      *modscan_kset;

static int __init resolve_symbols(void)
{
	struct kset **kset_ptr;

	modules_list_head = (struct list_head *)
		modscan_kallsyms("modules");
	if (!modules_list_head) {
		pr_err("modscan: symbol 'modules' not found\n");
		return -ENOENT;
	}
	pr_info("modscan: modules list @ %px\n", modules_list_head);

	/*
	 * "module_kset" is a struct kset * variable; kallsyms gives us
	 * the address of the pointer itself, so we need one dereference.
	 */
	kset_ptr = (struct kset **)modscan_kallsyms("module_kset");
	if (!kset_ptr || !*kset_ptr) {
		pr_err("modscan: symbol 'module_kset' not found\n");
		return -ENOENT;
	}
	modscan_kset = *kset_ptr;
	pr_info("modscan: module_kset @ %px\n", modscan_kset);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Snapshot helper: collect module names from kset under spinlock     */
/* ------------------------------------------------------------------ */

#define MODSCAN_MAX_SNAP 512

struct modscan_snap {
	char            name[MODULE_NAME_LEN];
	struct kobject *kobj;   /* pointer to the module's kobject in kset */
};

/*
 * snapshot_kset() - walk module_kset and record module names.
 *
 * Allocation is done before acquiring the spinlock (GFP_KERNEL is fine
 * outside atomic context). The spinlock is held only for the list walk
 * to minimise latency.
 *
 * Returns a kmalloc'd array on success (caller must kfree); negative
 * errno on failure. *out_n is set to the number of entries populated.
 */
static struct modscan_snap *snapshot_kset(int *out_n)
{
	struct modscan_snap   *snap;
	struct kobject        *kobj;
	struct module_kobject *mkobj;
	int n = 0;

	snap = kmalloc_array(MODSCAN_MAX_SNAP, sizeof(*snap), GFP_KERNEL);
	if (!snap)
		return ERR_PTR(-ENOMEM);

	spin_lock(&modscan_kset->list_lock);
	list_for_each_entry(kobj, &modscan_kset->list, entry) {
		if (n >= MODSCAN_MAX_SNAP)
			break;

		mkobj = container_of(kobj, struct module_kobject, kobj);

		/*
		 * mkobj->mod is NULL for the kset's own sentinel kobject
		 * and for sysfs pseudo-modules. Skip both.
		 */
		if (!mkobj->mod)
			continue;

		strncpy(snap[n].name, mkobj->mod->name, MODULE_NAME_LEN - 1);
		snap[n].name[MODULE_NAME_LEN - 1] = '\0';
		snap[n].kobj = kobj;
		n++;
	}
	spin_unlock(&modscan_kset->list_lock);

	*out_n = n;
	return snap;
}

/* ------------------------------------------------------------------ */
/*  Helpers called with module_mutex held                              */
/* ------------------------------------------------------------------ */

static bool name_in_modules_list(const char *name)
{
	struct module *mod;

	list_for_each_entry(mod, modules_list_head, list) {
		if (strcmp(mod->name, name) == 0)
			return true;
	}
	return false;
}

/* ------------------------------------------------------------------ */
/*  vmap_area_list scan — Volatility 3 method, executed in kernel space */
/* ------------------------------------------------------------------ */

/*
 * MODULE_STATE_UNFORMED was added in kernel 3.14.
 * On older kernels (e.g. 3.10/RHEL7) only LIVE/COMING/GOING (0-2) exist.
 * Defining it here allows the same state check (state > MODULE_STATE_UNFORMED)
 * to compile and work on both old and new kernels.
 */
#ifndef MODULE_STATE_UNFORMED
# define MODULE_STATE_UNFORMED 3
#endif

/*
 * struct vmap_area layout (x86-64) differs by kernel version:
 *
 * Linux < 5.7  (flags field before rb_node):
 *   +0   va_start   8B
 *   +8   va_end     8B
 *   +16  flags      8B  ← extra unsigned long
 *   +24  rb_node   24B  (3 × 8B pointer)
 *   +48  list.next  8B  ← VA_LIST_OFF = 48
 *   +56  list.prev  8B
 *   +64  llist_node 8B  (purge_list.next)
 *   +72  vm         8B  ← VA_VM_OFF   = 72
 *
 * Linux >= 5.7 (no separate flags, vm in union after list):
 *   +0   va_start   8B
 *   +8   va_end     8B
 *   +16  rb_node   24B
 *   +40  list.next  8B  ← VA_LIST_OFF = 40
 *   +48  list.prev  8B
 *   +56  vm (union) 8B  ← VA_VM_OFF   = 56
 *   +64  flags      8B
 *
 * To convert a list.next pointer to the struct start:
 *   vmap_area* = list_next_ptr - VA_LIST_OFF
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
# define VA_LIST_OFF  40UL
# define VA_VM_OFF    56UL
#else
# define VA_LIST_OFF  48UL
# define VA_VM_OFF    72UL
#endif

/* vm_struct layout (stable across versions, only need addr@+8 and flags@+24) */
#define VM_STRUCT_ADDR_OFF   8UL
#define VM_STRUCT_FLAGS_OFF  24UL

/* safe kernel read: handles unmapped/faulting addresses without crashing */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
# define vmscan_read(dst, src, n)  copy_from_kernel_nofault((dst), (src), (n))
#else
# define vmscan_read(dst, src, n)  probe_kernel_read((dst), (src), (n))
#endif

static inline bool vmscan_is_kptr(unsigned long p)
{
	return p != 0 && (p & 7) == 0 && p >= 0xffff000000000000UL;
}

/*
 * modscan_vmap_scan() - walk vmap_area_list from kernel space and scan
 * every VM_ALLOC region for a struct module signature.
 *
 * MUST be called with module_mutex held (calls name_in_modules_list).
 *
 * This is the exact equivalent of Volatility 3's linux.hidden_modules
 * plugin, but running live in kernel space:
 *   - Reads vmap_area_list directly (not via /proc/vmallocinfo)
 *   - Dereferences vm_struct to validate VM_ALLOC flag and addr match
 *   - Checks struct module signature fields in the mapped memory
 *   - Reports modules whose name is absent from the modules linked list
 */
static void modscan_vmap_scan(struct seq_file *m)
{
	unsigned long vmal_head, cur;
	int scanned = 0, vm_cnt = 0, candidates = 0, n_hidden = 0;

	vmal_head = modscan_kallsyms("vmap_area_list");
	if (!vmal_head) {
		seq_puts(m, "  (vmap_area_list not in kallsyms"
			      " — need CONFIG_KALLSYMS_ALL=y)\n");
		return;
	}
	seq_printf(m, "  vmap_area_list @ 0x%lx  "
		       "(layout: kernel %s 5.7, list_off=%lu vm_off=%lu)\n\n",
		   vmal_head,
		   LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) ? ">=" : "<",
		   VA_LIST_OFF, VA_VM_OFF);

	/* Read the sentinel head's first .next pointer */
	if (vmscan_read(&cur, (void *)vmal_head, sizeof(cur)) ||
	    !vmscan_is_kptr(cur)) {
		seq_puts(m, "  Cannot read vmap_area_list.next\n");
		return;
	}

	while (cur != vmal_head && scanned < 300000) {
		unsigned long va_base    = cur - VA_LIST_OFF;
		unsigned long va_start   = 0, va_end   = 0;
		unsigned long vm_ptr     = 0, list_next = 0;
		scanned++;

		/* Read the four fields we care about from the vmap_area */
		if (vmscan_read(&va_start,  (void *)(va_base + 0),          8) ||
		    vmscan_read(&va_end,    (void *)(va_base + 8),          8) ||
		    vmscan_read(&list_next, (void *)(va_base + VA_LIST_OFF), 8) ||
		    vmscan_read(&vm_ptr,    (void *)(va_base + VA_VM_OFF),   8))
			break;   /* kcore/page gone — stop traversal */

		/* Advance cur before any continue so we never stall */
		cur = list_next;
		if (!vmscan_is_kptr(cur))
			break;

		/* Skip free/lazy-purge areas (vm pointer is NULL or size value) */
		if (!vmscan_is_kptr(vm_ptr))
			continue;

		unsigned long va_size = va_end - va_start;
		if (va_size < 80 || va_size > 256UL * 1024 * 1024)
			continue;

		/*
		 * Validate via vm_struct:
		 *   vm->addr  (offset +8)  must equal va_start
		 *   vm->flags (offset +24) must have VM_ALLOC set
		 */
		unsigned long vm_addr_v = 0, vm_flags_v = 0;
		if (vmscan_read(&vm_addr_v,  (void *)(vm_ptr + VM_STRUCT_ADDR_OFF),  8) ||
		    vmscan_read(&vm_flags_v, (void *)(vm_ptr + VM_STRUCT_FLAGS_OFF), 8))
			continue;
		if (vm_addr_v != va_start)
			continue;
		if (!(vm_flags_v & VM_ALLOC))
			continue;

		vm_cnt++;

		/*
		 * struct module signature check (x86-64, stable layout):
		 *   +0   state     u32  : must be 0–3
		 *   +8   list.next u64  : valid kernel pointer, 8B-aligned
		 *   +16  list.prev u64  : same
		 *   +24  name[56]       : printable ASCII, NUL-terminated
		 */
		u32 state = 0xff;
		unsigned long mod_lnext = 0, mod_lprev = 0;
		char name[MODULE_NAME_LEN + 1] = {};

		if (vmscan_read(&state,     (void *)(va_start + 0),  4) ||
		    vmscan_read(&mod_lnext, (void *)(va_start + 8),  8) ||
		    vmscan_read(&mod_lprev, (void *)(va_start + 16), 8) ||
		    vmscan_read(name,       (void *)(va_start + 24), MODULE_NAME_LEN))
			continue;

		if (state > MODULE_STATE_UNFORMED)
			continue;
		if (!vmscan_is_kptr(mod_lnext) || !vmscan_is_kptr(mod_lprev))
			continue;

		/* Name validation: printable ASCII, non-empty, NUL-terminated */
		name[MODULE_NAME_LEN] = '\0';
		{
			char c0 = name[0];
			if (!((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z') ||
			      (c0 >= '0' && c0 <= '9') || c0 == '_'))
				continue;
		}
		{
			int i, nlen = -1;
			for (i = 0; i < MODULE_NAME_LEN; i++) {
				if (name[i] == '\0') { nlen = i; break; }
				if ((unsigned char)name[i] < 0x20 ||
				    (unsigned char)name[i] >= 0x7f)
					break;
			}
			if (nlen <= 0)
				continue;
		}

		/* Chain cross-check: list.next - 8 should also have valid state */
		{
			u32 next_state = 0xff;
			if (vmscan_read(&next_state,
					(void *)(mod_lnext - 8), 4) ||
			    next_state > MODULE_STATE_UNFORMED)
				continue;
		}

		candidates++;

		/* Compare against the live modules list (held under module_mutex) */
		if (!name_in_modules_list(name)) {
			seq_printf(m,
				   "VMAP-HIDDEN  %-20s  @ 0x%lx"
				   "  size=%-8lu  state=%u\n",
				   name, va_start, va_size, state);
			n_hidden++;
		}
	}

	seq_printf(m,
		   "  Scanned: %d vmap_areas | VM_ALLOC: %d"
		   " | module candidates: %d | hidden: %d\n",
		   scanned, vm_cnt, candidates, n_hidden);
	if (n_hidden == 0)
		seq_puts(m, "  (no hidden modules found by vmap_area scan)\n");
}

/* ------------------------------------------------------------------ */
/*  Raw module range scan — Volatility 3 equivalent for live kernels   */
/* ------------------------------------------------------------------ */

/*
 * On kernel 3.10 (RHEL7), a sophisticated rootkit can hide itself by
 * cleaning up ALL kernel tracking structures:
 *   - list_del()   from the modules linked list
 *   - kobject_del() from module_kset (sysfs)
 *   - clearing     vmap_area.vm pointer (or removing from vmap_area_list)
 *
 * After this, NO linked-list-based scanner can find the module.
 * Volatility 3 finds it by scanning a raw memory dump for struct module
 * signatures. This function is the live-kernel equivalent:
 *
 *   Scan every page in [MODULES_VADDR, MODULES_END] with
 *   probe_kernel_read() / copy_from_kernel_nofault().
 *   The hidden module's code/data is still mapped (it's still running),
 *   so the reads succeed and the struct module signature is visible.
 *
 * This does NOT rely on:
 *   modules list, module_kset, vmap_area_list, /proc/modules,
 *   /sys/module/, /proc/vmallocinfo — all of which can be tampered.
 *
 * MODULES_VADDR / MODULES_END on x86-64:
 *   kernel 3.10-6.x:  0xffffffffa0000000 – 0xfffffffffff00000
 *   (~1.5 GB range, ~390K pages; ~80-400 ms scan with nofault probing)
 *
 * WHY THE PREVIOUS VERSION ONLY FOUND 13 OF 106 MODULES:
 *
 *   struct module is NOT at offset 0 of its vmalloc allocation.
 *   It lives inside the .data section (.gnu.linkonce.this_module),
 *   which comes after .text and .rodata in the allocation layout:
 *
 *     [vmalloc base]  .text  .rodata  .data←struct module  .bss
 *
 *   Reading only the first 80 bytes of each page misses every module
 *   whose struct is at a non-zero page-relative offset.
 *
 * FIX — sliding window within each mapped page:
 *
 *   1. Read the entire page (4096 B) with one vmscan_read call.
 *      Unmapped pages fail instantly (-EFAULT); mapped pages are cheap.
 *   2. Slide an 80-byte window at 8-byte steps across the page.
 *      (struct module is always at least 8-byte aligned.)
 *   3. Apply the 5-stage filter at each window position.
 *
 *   This catches struct module at any 8B-aligned offset within any
 *   mapped page — exactly what Volatility 3 does on a raw memory dump.
 *
 * Performance (390 K pages, ~1 K mapped):
 *   Unmapped: 390 K × ~300 ns = ~120 ms  (one fast fault per page)
 *   Mapped:   1 K × [(4 KB read) + 501 windows × fast filter] ≈ 10 ms
 *   Total: < 200 ms
 */

/* Candidate found during phase-1 scan (before mutex is acquired) */
#define MODSCAN_MAX_CANDS 512

/*
 * LIST_POISON1/2 are set by list_del() in the deleted entry's own next/prev
 * fields.  On x86-64: POISON_POINTER_DELTA = 0xdead000000000000
 *   LIST_POISON1 = 0xdead000000000100
 *   LIST_POISON2 = 0xdead000000000200
 * These fail vmscan_is_kptr() (< 0xffff...) but are a definitive indicator
 * of a module that was removed via list_del() — i.e. DKOM-hidden.
 * Accept them explicitly so we don't filter out DKOM victims.
 */
#define MODSCAN_POISON1  0xdead000000000100UL
#define MODSCAN_POISON2  0xdead000000000200UL

static inline bool vmscan_is_poison(unsigned long p)
{
	return p == MODSCAN_POISON1 || p == MODSCAN_POISON2;
}

struct modscan_cand {
	unsigned long addr;   /* exact virtual address of struct module */
	u32           state;
	u8            dkom_poisoned; /* list pointers were LIST_POISON — DKOM */
	char          name[MODULE_NAME_LEN + 1];
};

static void modscan_raw_scan(struct seq_file *m)
{
	struct modscan_cand *cands;
	u8                  *page_buf;
	int  ncands = 0, n_visible = 0, hidden = 0, mapped_pages = 0;
	unsigned long addr;

#ifndef MODULES_VADDR
	seq_puts(m, "  (MODULES_VADDR not defined — x86-64 only)\n");
	return;
#else
	const unsigned long raw_start = MODULES_VADDR;
	const unsigned long raw_end   = MODULES_END;

	seq_printf(m,
		   "  Raw scan (sliding window): 0x%lx – 0x%lx  (%lu pages)\n\n",
		   raw_start, raw_end,
		   (raw_end - raw_start) >> PAGE_SHIFT);

	cands = kmalloc_array(MODSCAN_MAX_CANDS, sizeof(*cands), GFP_KERNEL);
	if (!cands) {
		seq_puts(m, "  OOM — cands\n");
		return;
	}

	/*
	 * Allocate one page buffer on the heap (4 KB on kernel stack is too
	 * risky — default stack is 8–16 KB and we have call-chain depth here).
	 */
	page_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!page_buf) {
		seq_puts(m, "  OOM — page_buf\n");
		kfree(cands);
		return;
	}

	/* ── Phase 1: raw page scan, no lock ─────────────────────────────── */
	for (addr = raw_start;
	     addr < raw_end && ncands < MODSCAN_MAX_CANDS;
	     addr += PAGE_SIZE) {

		unsigned int off;

		/*
		 * Read the entire page at once.
		 * Unmapped pages fault immediately — cheap.
		 * Mapped pages give us 4096 bytes to slide over.
		 */
		if (vmscan_read(page_buf, (void *)addr, PAGE_SIZE))
			continue;

		mapped_pages++;

		/*
		 * Slide an 80-byte window at 8-byte steps.
		 * 80 bytes covers: state(4)+pad(4)+list.next(8)+list.prev(8)+name(56).
		 * The window must fit entirely within the page.
		 */
		for (off = 0; off + 80 <= (unsigned int)PAGE_SIZE; off += 8) {

			u32           state;
			unsigned long lnext, lprev;
			char          name[MODULE_NAME_LEN + 1];
			int           i, nlen;
			char          c0;
			bool          is_dkom;

			/* ── Filter [1]: state ∈ {0,1,2,3} ────────────────── */
			memcpy(&state, page_buf + off + 0, 4);
			if (state > MODULE_STATE_UNFORMED)
				continue;

			/* ── Filter [2]: name[0] is alphanumeric/_ ─────────── *
			 * Cheap early exit — avoids pointer reads for most windows.
			 */
			c0 = (char)page_buf[off + 24];
			if (!((c0 >= 'a' && c0 <= 'z') ||
			      (c0 >= 'A' && c0 <= 'Z') ||
			      (c0 >= '0' && c0 <= '9') || c0 == '_'))
				continue;

			/* ── Filter [3]: list.next / list.prev ─────────────── *
			 * Accept either:
			 *   (a) canonical kernel pointer — module still in list,
			 *   (b) LIST_POISON1/2 — module removed via list_del().
			 * LIST_POISON is 0xdead000000000100/200: fails vmscan_is_kptr
			 * (< 0xffff...) but is definitive evidence of DKOM hiding.
			 * Any other value (NULL, arbitrary garbage) is rejected.
			 */
			memcpy(&lnext, page_buf + off + 8,  8);
			memcpy(&lprev, page_buf + off + 16, 8);
			if (!vmscan_is_kptr(lnext) && !vmscan_is_poison(lnext))
				continue;
			if (!vmscan_is_kptr(lprev) && !vmscan_is_poison(lprev))
				continue;

			/* True when list_del() poisoned the module's list ptrs */
			is_dkom = vmscan_is_poison(lnext) || vmscan_is_poison(lprev);

			/* ── Filter [4]: full name validation ──────────────── */
			memcpy(name, page_buf + off + 24, MODULE_NAME_LEN);
			name[MODULE_NAME_LEN] = '\0';
			nlen = -1;
			for (i = 0; i < MODULE_NAME_LEN; i++) {
				if (name[i] == '\0') { nlen = i; break; }
				if ((unsigned char)name[i] < 0x20 ||
				    (unsigned char)name[i] >= 0x7f)
					break;
			}
			if (nlen <= 0)
				continue;

			/* ── Filter [5]: chain cross-check ─────────────────── *
			 * For live-list modules: walk to the neighbour struct
			 * and verify its state — catches false positives from
			 * data that happens to look like a module header.
			 *
			 * For DKOM-poisoned modules: skip — reading from POISON
			 * addresses would fault.  The POISON values ARE the proof.
			 */
			if (!is_dkom) {
				u32 ns = 0xff, ps = 0xff;

				if (vmscan_read(&ns, (void *)(lnext - 8), 4) ||
				    ns > MODULE_STATE_UNFORMED)
					continue;
				if (vmscan_read(&ps, (void *)(lprev - 8), 4) ||
				    ps > MODULE_STATE_UNFORMED)
					continue;
			}

			/* ── Filter [6]: mkobj.kobj.name cross-check ────────── *
			 * struct module layout (stable across x86-64 kernels):
			 *   +80  mkobj.kobj.name  — const char * pointing to the
			 *                           module name string in .data
			 *
			 * For a real struct module, that pointer dereferences to
			 * the same string as +24.  For a false positive (random
			 * data inside another module that passed filters 1-5),
			 * offset +80 is unlikely to point back to that name.
			 *
			 * Skipped for DKOM-poisoned entries: the rootkit may
			 * also have called kobject_del() which clears kobj->name.
			 * For those, LIST_POISON evidence is sufficient.
			 */
			if (!is_dkom) {
				unsigned long kn_ptr = 0;
				char kn_buf[MODULE_NAME_LEN + 1];
				bool f6_pass = false;

				do {
					/* kobj.name sits at window-offset +80 */
					if (off + 88 <= (unsigned int)PAGE_SIZE)
						memcpy(&kn_ptr,
						       page_buf + off + 80, 8);
					else if (vmscan_read(&kn_ptr,
							     (void *)(addr + off + 80),
							     8))
						break;

					if (!vmscan_is_kptr(kn_ptr))
						break;

					memset(kn_buf, 0, sizeof(kn_buf));
					if (vmscan_read(kn_buf, (void *)kn_ptr,
							MODULE_NAME_LEN))
						break;
					kn_buf[MODULE_NAME_LEN] = '\0';

					if (strncmp(kn_buf, name, MODULE_NAME_LEN) == 0)
						f6_pass = true;
				} while (0);

				if (!f6_pass)
					continue;
			}

			/* ── Deduplication: skip if same name already found ── */
			{
				int dup = 0, k;

				for (k = 0; k < ncands; k++) {
					if (strncmp(cands[k].name, name,
						    MODULE_NAME_LEN) == 0) {
						dup = 1;
						break;
					}
				}
				if (dup)
					continue;
			}

			/* ── Record candidate ───────────────────────────────── */
			if (ncands < MODSCAN_MAX_CANDS) {
				cands[ncands].addr         = addr + off;
				cands[ncands].state        = state;
				cands[ncands].dkom_poisoned = is_dkom ? 1 : 0;
				memcpy(cands[ncands].name, name,
				       MODULE_NAME_LEN + 1);
				ncands++;
			}
		}
	}

	kfree(page_buf);

	/* ── Phase 2: compare against modules list (brief mutex hold) ─────── */
	if (ncands > 0) {
		if (mutex_lock_killable(&module_mutex) == 0) {
			int i;
			for (i = 0; i < ncands; i++) {
				if (name_in_modules_list(cands[i].name)) {
					n_visible++;
				} else {
					seq_printf(m,
						   "RAW-HIDDEN   %-20s"
						   "  @ 0x%lx  state=%u%s\n",
						   cands[i].name,
						   cands[i].addr,
						   cands[i].state,
						   cands[i].dkom_poisoned
						   ? "  [LIST_POISON -- DKOM via list_del]"
						   : "");
					hidden++;
				}
			}
			mutex_unlock(&module_mutex);
		} else {
			seq_puts(m, "  (interrupted — module_mutex unavailable)\n");
		}
	}

	kfree(cands);

	seq_printf(m,
		   "  Mapped pages: %d | Signatures found: %d"
		   " (%d visible, %d HIDDEN)\n",
		   mapped_pages, ncands, n_visible, hidden);
	if (mapped_pages == 0)
		seq_puts(m, "  NOTE: No mapped pages — rebuild modscan.ko for"
			    " this kernel version\n");
	else if (hidden == 0 && ncands > 0)
		seq_puts(m, "  (all found modules are in the modules list)\n");
#endif /* MODULES_VADDR */
}

/* ------------------------------------------------------------------ */
/*  /proc/modscan — read: scan for hidden modules                      */
/* ------------------------------------------------------------------ */

static int modscan_show(struct seq_file *m, void *v)
{
	struct modscan_snap *snap;
	int i, n = 0, n_hidden = 0;

	snap = snapshot_kset(&n);
	if (IS_ERR(snap))
		return PTR_ERR(snap);

	seq_puts(m, "=== ModScan: Hidden Module Scan ===\n\n");

	if (mutex_lock_killable(&module_mutex)) {
		kfree(snap);
		return -EINTR;
	}

	for (i = 0; i < n; i++) {
		/* Skip ourselves */
		if (strcmp(snap[i].name, THIS_MODULE->name) == 0)
			continue;
		if (!name_in_modules_list(snap[i].name)) {
			seq_printf(m, "HIDDEN  %s\n", snap[i].name);
			n_hidden++;
		}
	}

	mutex_unlock(&module_mutex);
	kfree(snap);

	if (n_hidden == 0)
		seq_puts(m, "(no hidden modules detected)\n");
	else
		seq_printf(m, "\n%d hidden module(s) found.\n", n_hidden);

	/*
	 * Sysfs tamper check — for each module still in the kset, verify that
	 * its kernfs_node (kobj->sd) is non-NULL.
	 *
	 * kobject_del() removes the kobject from both the kset list and sysfs by
	 * calling kernfs_remove() which zeroes kobj->sd.  A rootkit that calls
	 * kobject_del() before list_del() leaves the module invisible to both
	 * /sys/module/ and /proc/modules, so the standard DKOM check above would
	 * miss it — but the kobject might still be in the kset list with sd==NULL.
	 *
	 * A rootkit that calls kernfs_remove() directly (without list_del on the
	 * kset) is caught here: the kobject IS in the kset scan above (snapshot),
	 * but its sysfs entry is gone.
	 */
	seq_puts(m, "\n=== Sysfs Integrity Check (kset vs kernfs) ===\n\n");
	int n_sysfs_tampered = 0;
	for (i = 0; i < n; i++) {
		if (strcmp(snap[i].name, THIS_MODULE->name) == 0)
			continue;
		/*
		 * kobj->sd is set by kobject_add() and cleared by kobject_del().
		 * If it is NULL the sysfs entry no longer exists even though the
		 * kobject is still linked in the kset.
		 */
		if (!snap[i].kobj->sd) {
			seq_printf(m, "SYSFS-TAMPER  %s  "
				   "(kset entry present, kernfs node gone)\n",
				   snap[i].name);
			n_sysfs_tampered++;
		}
	}
	if (n_sysfs_tampered == 0)
		seq_puts(m, "(sysfs consistent with kset — no tampering detected)\n");
	else
		seq_printf(m, "\n%d sysfs-tampered module(s) found.\n",
			   n_sysfs_tampered);

	seq_puts(m, "\nTo restore: echo 'restore <name>' > /proc/modscan\n"
	            "           echo 'restore-addr <hex>' > /proc/modscan\n");

	/*
	 * === Module metadata audit ===
	 *
	 * For each module in the modules list, show core_size, init_size, refcnt.
	 * Rootkits set these to 0xFFFFFFFE (-2 as signed) to impede removal.
	 */
	seq_puts(m, "\n=== Module Metadata Audit (detect field corruption) ===\n\n");
	{
		struct module *mod;
		int n_corrupt = 0;

		if (mutex_lock_killable(&module_mutex) == 0) {
			list_for_each_entry(mod, modules_list_head, list) {
				int rc = atomic_read(&mod->refcnt);
				unsigned int csz = mod->core_size;
				unsigned int isz = mod->init_size;
				/* Legitimate: csz > 0, isz >= 0, rc >= 0 */
				if (rc < 0 || csz == 0 || csz > (256u << 20)) {
					seq_printf(m,
						   "CORRUPT-FIELDS  %-20s"
						   "  core_sz=%u init_sz=%u refcnt=%d\n",
						   mod->name, csz, isz, rc);
					n_corrupt++;
				}
			}
			mutex_unlock(&module_mutex);
		}
		if (n_corrupt == 0)
			seq_puts(m, "  (all module fields look normal)\n");
		else
			seq_printf(m,
				   "  %d module(s) with corrupted fields.\n"
				   "  Fix refcnt before rmmod: echo 'fix-refcnt <hex>'"
				   " > /proc/modscan\n", n_corrupt);
	}

	/*
	 * === Syscall table audit ===
	 *
	 * Check whether sys_call_table[__NR_delete_module] still points into
	 * legitimate kernel text.  A hooked entry explains why rmmod returns
	 * ENOENT for modules that lsmod can see.
	 */
	seq_puts(m, "\n=== Syscall Table Audit ===\n\n");
	{
		unsigned long *sct;
		unsigned long fn, ks, ke;

		sct = (unsigned long *)modscan_kallsyms("sys_call_table");
		ks  = modscan_kallsyms("_stext");
		ke  = modscan_kallsyms("_etext");

		if (!sct || !ks || !ke) {
			seq_puts(m, "  (sys_call_table/_stext/_etext not in"
				    " kallsyms — need CONFIG_KALLSYMS_ALL=y)\n");
		} else {
			/* __NR_delete_module = 176 on x86-64 */
			fn = sct[176];
			if (fn >= ks && fn <= ke) {
				seq_printf(m,
					   "  sys_call_table[176] (delete_module)"
					   " = 0x%lx  [OK — in kernel text]\n",
					   fn);
			} else {
				seq_printf(m,
					   "SYSCALL-HOOK  sys_call_table[176]"
					   " = 0x%lx  [OUTSIDE kernel text"
					   " 0x%lx-0x%lx] — rmmod is hooked!\n",
					   fn, ks, ke);
			}

			/* Also check sys_init_module [NR=175] for completeness */
			fn = sct[175];
			if (fn < ks || fn > ke)
				seq_printf(m,
					   "SYSCALL-HOOK  sys_call_table[175]"
					   " (init_module) = 0x%lx  [OUTSIDE"
					   " kernel text]\n", fn);
		}
	}

	/*
	 * === vmap_area_list scan (Volatility 3 method) ===
	 *
	 * Walk the kernel's vmap_area_list directly (not via /proc/vmallocinfo)
	 * and scan every VM_ALLOC region for a struct module signature.
	 * This catches modules hidden by list_del() even when kset/sysfs have
	 * also been cleaned up (kobject_del), i.e. when the kset scan above
	 * would miss them.
	 */
	seq_puts(m, "\n=== vmap_area_list Scan (Volatility 3 Method) ===\n\n");
	if (mutex_lock_killable(&module_mutex) == 0) {
		modscan_vmap_scan(m);
		mutex_unlock(&module_mutex);
	}

	/*
	 * Raw module range scan — last resort, catches rootkits that clean up
	 * ALL tracking structures (modules list + kset + vmap_area_list).
	 * Directly probes every page in [MODULES_VADDR, MODULES_END] for a
	 * struct module signature. Does not acquire any lock during the scan.
	 * Equivalent to what Volatility 3 does on a live memory dump.
	 */
	seq_puts(m, "\n=== Raw Module Range Scan (Last Resort) ===\n\n");
	modscan_raw_scan(m);

	return 0;
}

static int modscan_open(struct inode *inode, struct file *file)
{
	return single_open(file, modscan_show, NULL);
}

/* ------------------------------------------------------------------ */
/*  /proc/modscan — write: restore a hidden module                     */
/* ------------------------------------------------------------------ */

/*
 * modscan_write() — parse "restore <name>" and re-link the module.
 *
 * Lock ordering (consistent with kernel internal ordering):
 *   1. kset->list_lock  (spinlock)  — find struct module * by name
 *   2. module_mutex     (mutex)     — re-link into modules list
 *
 * The spinlock is released before acquiring the mutex because
 * mutex_lock may sleep, which is forbidden in atomic context.
 */
/*
 * modscan_restore_raw() — restore a module whose struct module address was
 * discovered by the raw memory scan (modscan_raw_scan).
 *
 * Used when the rootkit has removed the module from ALL kernel tracking
 * structures (modules list + kset/sysfs), leaving no linked-list path to
 * find the struct module *.  The raw scan gives us the virtual address
 * directly; this function validates it and re-links the module.
 *
 * Safety checks before touching anything:
 *   1. Address in [MODULES_VADDR, MODULES_END), 8-byte aligned
 *   2. state field valid (0-3)
 *   3. name field printable ASCII, non-empty
 *   4. Module is NOT already in the modules list (idempotent)
 */
#ifdef MODULES_VADDR
static ssize_t modscan_restore_raw(unsigned long raw_addr, size_t count)
{
	struct module *mod;
	u32 state = 0xff;
	char name[MODULE_NAME_LEN + 1] = {};
	int i, nlen = -1;

	/* [1] Range and alignment */
	if (raw_addr < MODULES_VADDR || raw_addr >= MODULES_END ||
	    (raw_addr & 7)) {
		pr_err("modscan: restore-addr 0x%lx out of range/misaligned\n",
		       raw_addr);
		return -ERANGE;
	}

	/* [2] state */
	if (vmscan_read(&state, (void *)raw_addr, 4) ||
	    state > MODULE_STATE_UNFORMED) {
		pr_err("modscan: restore-addr 0x%lx: invalid state\n", raw_addr);
		return -EINVAL;
	}

	/* [3] name */
	if (vmscan_read(name, (void *)(raw_addr + 24), MODULE_NAME_LEN)) {
		pr_err("modscan: restore-addr 0x%lx: cannot read name\n",
		       raw_addr);
		return -EINVAL;
	}
	name[MODULE_NAME_LEN] = '\0';
	for (i = 0; i < MODULE_NAME_LEN; i++) {
		if (name[i] == '\0') { nlen = i; break; }
		if ((unsigned char)name[i] < 0x20 ||
		    (unsigned char)name[i] >= 0x7f)
			break;
	}
	if (nlen <= 0) {
		pr_err("modscan: restore-addr 0x%lx: invalid name\n", raw_addr);
		return -EINVAL;
	}

	mod = (struct module *)raw_addr;

	/* [4] Re-link under module_mutex */
	if (mutex_lock_killable(&module_mutex))
		return -EINTR;

	if (name_in_modules_list(name)) {
		mutex_unlock(&module_mutex);
		pr_info("modscan: '%s' is already in the modules list\n", name);
		return -EEXIST;
	}

	/*
	 * Re-insert at the tail of the modules list.
	 * list_add() overwrites mod->list.next/prev, clearing any LIST_POISON
	 * values left by the rootkit's list_del() call.
	 * After this, lsmod and rmmod will find the module again.
	 */
	list_add_tail(&mod->list, modules_list_head);
	mutex_unlock(&module_mutex);

	pr_info("modscan: module '%s' @ 0x%lx restored to modules list\n",
		name, raw_addr);
	return count;
}
#endif /* MODULES_VADDR */

static ssize_t modscan_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	/* longest command: "restore-addr 0xffffffffffffffff\n" = 32 bytes */
	char kbuf[64];
	char modname[MODULE_NAME_LEN];
	struct kobject        *kobj;
	struct module_kobject *mkobj;
	struct module         *target = NULL;
	size_t len;

	len = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;
	kbuf[len] = '\0';

	/* Strip trailing newline from shell echo */
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[--len] = '\0';

	/*
	 * Command: restore-addr <hex>
	 *
	 * Use when the rootkit has also removed the module from module_kset
	 * (so "restore <name>" cannot find it).  Supply the address printed
	 * by the Raw Module Range Scan section of /proc/modscan.
	 *
	 * Example:
	 *   echo 'restore-addr 0xffffffffc0931a80' > /proc/modscan
	 */
#ifdef MODULES_VADDR
	if (strncmp(kbuf, "restore-addr ", 13) == 0) {
		unsigned long raw_addr = 0;

		if (kstrtoul(kbuf + 13, 16, &raw_addr)) {
			pr_err("modscan: restore-addr: bad hex address\n");
			return -EINVAL;
		}
		return modscan_restore_raw(raw_addr, count);
	}
#endif

	/*
	 * Command: fix-refcnt <hex>
	 *
	 * A rootkit that sets mod->core_size = 0xFFFFFFFE and
	 * atomic_set(&mod->refcnt, -2) prevents clean removal even after the
	 * module is restored to the modules list.  This command resets those
	 * fields to legitimate values so rmmod --force can proceed.
	 *
	 * Supply the address from the Raw Module Range Scan output.
	 *
	 * Example:
	 *   echo 'fix-refcnt 0xffffffffc0931a80' > /proc/modscan
	 */
#ifdef MODULES_VADDR
	if (strncmp(kbuf, "fix-refcnt ", 11) == 0) {
		unsigned long fix_addr = 0;
		struct module *fmod;
		u32 state = 0xff;
		char fname[MODULE_NAME_LEN + 1] = {};

		if (kstrtoul(kbuf + 11, 16, &fix_addr)) {
			pr_err("modscan: fix-refcnt: bad hex address\n");
			return -EINVAL;
		}
		if (fix_addr < MODULES_VADDR || fix_addr >= MODULES_END ||
		    (fix_addr & 7)) {
			pr_err("modscan: fix-refcnt: address out of range\n");
			return -ERANGE;
		}
		if (vmscan_read(&state, (void *)fix_addr, 4) ||
		    state > MODULE_STATE_UNFORMED) {
			pr_err("modscan: fix-refcnt: invalid state at 0x%lx\n",
			       fix_addr);
			return -EINVAL;
		}
		if (vmscan_read(fname, (void *)(fix_addr + 24),
				MODULE_NAME_LEN))
			return -EINVAL;
		fname[MODULE_NAME_LEN] = '\0';

		fmod = (struct module *)fix_addr;

		/*
		 * Reset only the fields the rootkit corrupts to block removal:
		 *   refcnt  → 0  (module has no users)
		 *   state   → MODULE_STATE_LIVE  (was left as LIVE but be explicit)
		 *
		 * We do NOT guess at core_size/init_size; those are only used
		 * for display in /proc/modules and for the freeing path, which
		 * we skip here.  rmmod --force will trigger the exit() path
		 * without checking size.
		 */
		atomic_set(&fmod->refcnt, 0);
		fmod->state = MODULE_STATE_LIVE;

		pr_info("modscan: fix-refcnt: '%s' @ 0x%lx"
			" — refcnt reset to 0, state set LIVE\n",
			fname, fix_addr);
		return count;
	}
#endif

	if (sscanf(kbuf, "restore %55s", modname) != 1) {
		pr_err("modscan: unknown command '%s'\n"
		       "modscan: usage:\n"
		       "  echo 'restore <name>' > /proc/modscan\n"
		       "  echo 'restore-addr <hex>' > /proc/modscan\n"
		       "  echo 'fix-refcnt <hex>' > /proc/modscan\n",
		       kbuf);
		return -EINVAL;
	}

	/* Step 1 — find the module in the kset (under spinlock) */
	spin_lock(&modscan_kset->list_lock);
	list_for_each_entry(kobj, &modscan_kset->list, entry) {
		mkobj = container_of(kobj, struct module_kobject, kobj);
		if (!mkobj->mod)
			continue;
		if (strcmp(mkobj->mod->name, modname) == 0) {
			target = mkobj->mod;
			break;
		}
	}
	spin_unlock(&modscan_kset->list_lock);

	if (!target) {
		pr_err("modscan: '%s' not found in module kset\n"
		       "modscan: if the rootkit removed it from kset too, use:\n"
		       "  echo 'restore-addr <hex>' > /proc/modscan\n"
		       "  (address from the Raw Module Range Scan output)\n",
		       modname);
		return -ENOENT;
	}

	/* Step 2 — re-link under module_mutex */
	if (mutex_lock_killable(&module_mutex))
		return -EINTR;

	if (name_in_modules_list(modname)) {
		mutex_unlock(&module_mutex);
		pr_info("modscan: '%s' is already in the modules list\n",
			modname);
		return -EEXIST;
	}

	/*
	 * Re-insert at the head of the modules list.
	 * list_add() links:  modules_list_head <-> target->list <-> prev-first
	 *
	 * After this, /proc/modules (lsmod) and rmmod will find the module.
	 */
	list_add(&target->list, modules_list_head);
	mutex_unlock(&module_mutex);

	pr_info("modscan: module '%s' restored to modules list\n", modname);
	return count;
}

/* ------------------------------------------------------------------ */
/*  proc entry registration (proc_ops ≥ 5.6, file_operations < 5.6)  */
/* ------------------------------------------------------------------ */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops modscan_pops = {
	.proc_open    = modscan_open,
	.proc_read    = seq_read,
	.proc_write   = modscan_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};
# define MODSCAN_FOPS (&modscan_pops)
#else
static const struct file_operations modscan_fops = {
	.owner   = THIS_MODULE,
	.open    = modscan_open,
	.read    = seq_read,
	.write   = modscan_write,
	.llseek  = seq_lseek,
	.release = single_release,
};
# define MODSCAN_FOPS (&modscan_fops)
#endif

#define MODSCAN_PROC_NAME "modscan"

static struct proc_dir_entry *modscan_pde;

/* ------------------------------------------------------------------ */
/*  Module init / exit                                                 */
/* ------------------------------------------------------------------ */

static int __init modscan_init(void)
{
	int ret;

	ret = resolve_kallsyms();
	if (ret)
		return ret;

	ret = resolve_symbols();
	if (ret)
		return ret;

	modscan_pde = proc_create(MODSCAN_PROC_NAME, 0600, NULL, MODSCAN_FOPS);
	if (!modscan_pde) {
		pr_err("modscan: proc_create failed\n");
		return -ENOMEM;
	}

	pr_info("modscan: loaded — /proc/%s ready\n", MODSCAN_PROC_NAME);
	pr_info("modscan:   scan    : cat /proc/modscan\n");
	pr_info("modscan:   restore : echo 'restore <name>' > /proc/modscan\n");
	return 0;
}

static void __exit modscan_exit(void)
{
	proc_remove(modscan_pde);
	pr_info("modscan: unloaded\n");
}

module_init(modscan_init);
module_exit(modscan_exit);
