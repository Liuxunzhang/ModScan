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
static struct list_head *modules_list_head;
static struct kset      *modscan_kset;
static struct mutex     *modscan_module_mutex;

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

	/*
	 * module_mutex is no longer exported on kernels >= 6.1.
	 * Resolve it via kallsyms.
	 */
	modscan_module_mutex = (struct mutex *)
		modscan_kallsyms("module_mutex");
	if (!modscan_module_mutex) {
		pr_err("modscan: symbol 'module_mutex' not found\n");
		return -ENOENT;
	}
	pr_info("modscan: module_mutex @ %px\n", modscan_module_mutex);

	return 0;
}

/* ------------------------------------------------------------------ */
/*  Snapshot helper: collect module names from kset under spinlock     */
/* ------------------------------------------------------------------ */

#define MODSCAN_MAX_SNAP 512

struct modscan_snap {
	char name[MODULE_NAME_LEN];
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
/*  Kallsyms orphan detection (detects rootkits that also tamper kset) */
/* ------------------------------------------------------------------ */

/*
 * Even if a rootkit removes itself from both the modules list AND
 * the module_kset, its symbols typically remain in kallsyms.
 * Module symbols appear as:  addr type symbol_name  [module_name]
 * We walk kallsyms and find module names that are NOT in the modules list.
 */

#define MODSCAN_ORPHAN_MAX 64

struct modscan_orphan {
	char name[MODULE_NAME_LEN];
	int  sym_count;
};

static int scan_kallsyms_orphans(struct modscan_orphan *orphans, int max)
{
	struct modscan_sym {
		char modname[MODULE_NAME_LEN];
	} *syms;
	int n_syms = 0, n_orphans = 0;
	const int max_syms = 8192;
	char line[256];
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	int i, j;

	syms = kmalloc_array(max_syms, sizeof(*syms), GFP_KERNEL);
	if (!syms)
		return -ENOMEM;

	f = filp_open("/proc/kallsyms", O_RDONLY, 0);
	if (IS_ERR(f)) {
		kfree(syms);
		return PTR_ERR(f);
	}

	while (n_syms < max_syms) {
		char *bracket;
		char *end;
		int modlen;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		n = kernel_read(f, line, sizeof(line) - 1, &pos);
#else
		n = kernel_read(f, pos, line, sizeof(line) - 1);
		pos += n;
#endif
		if (n <= 0)
			break;
		line[n] = '\0';

		/* Find the [module_name] suffix */
		bracket = strchr(line, '[');
		if (!bracket)
			continue;
		bracket++;

		end = strchr(bracket, ']');
		if (!end)
			continue;

		modlen = (int)(end - bracket);
		if (modlen <= 0 || modlen >= MODULE_NAME_LEN)
			continue;

		memcpy(syms[n_syms].modname, bracket, modlen);
		syms[n_syms].modname[modlen] = '\0';
		n_syms++;
	}

	filp_close(f, NULL);

	/* Check each module name against the modules list */
	for (i = 0; i < n_syms; i++) {
		bool found;

		/* Skip built-in kernel symbols and ourselves */
		if (strcmp(syms[i].modname, THIS_MODULE->name) == 0)
			continue;

		/* Skip if already in modules list */
		if (name_in_modules_list(syms[i].modname))
			continue;

		/* Check if already in orphan list */
		found = false;
		for (j = 0; j < n_orphans; j++) {
			if (strcmp(orphans[j].name, syms[i].modname) == 0) {
				orphans[j].sym_count++;
				found = true;
				break;
			}
		}
		if (!found && n_orphans < max) {
			strncpy(orphans[n_orphans].name, syms[i].modname,
				MODULE_NAME_LEN - 1);
			orphans[n_orphans].name[MODULE_NAME_LEN - 1] = '\0';
			orphans[n_orphans].sym_count = 1;
			n_orphans++;
		}
	}

	kfree(syms);
	return n_orphans;
}

/* ------------------------------------------------------------------ */
/*  /proc/modscan — read: scan for hidden modules                      */
/* ------------------------------------------------------------------ */

static int modscan_show(struct seq_file *m, void *v)
{
	struct modscan_snap *snap;
	struct modscan_orphan *orphans;
	int i, n = 0, n_hidden = 0, n_orphan = 0;

	seq_puts(m, "=== ModScan: Hidden Module Scan ===\n\n");

	/* ------------------------------------------------------------------ */
	/* Phase 1: kset vs modules list (DKOM list_del detection)             */
	/* ------------------------------------------------------------------ */

	snap = snapshot_kset(&n);
	if (IS_ERR(snap))
		return PTR_ERR(snap);

	if (mutex_lock_killable(modscan_module_mutex)) {
		kfree(snap);
		return -EINTR;
	}

	for (i = 0; i < n; i++) {
		if (strcmp(snap[i].name, THIS_MODULE->name) == 0)
			continue;
		if (!name_in_modules_list(snap[i].name)) {
			seq_printf(m, "HIDDEN  %s\n", snap[i].name);
			n_hidden++;
		}
	}

	mutex_unlock(modscan_module_mutex);
	kfree(snap);

	/* ------------------------------------------------------------------ */
	/* Phase 2: kallsyms orphans (detects rootkits that also tamper kset)  */
	/* ------------------------------------------------------------------ */

	orphans = kmalloc_array(MODSCAN_ORPHAN_MAX, sizeof(*orphans),
				GFP_KERNEL);
	if (!orphans) {
		seq_puts(m, "WARNING: kallsyms orphan scan skipped (ENOMEM)\n");
		goto summary;
	}

	n_orphan = scan_kallsyms_orphans(orphans, MODSCAN_ORPHAN_MAX);
	if (n_orphan < 0) {
		seq_printf(m, "WARNING: kallsyms orphan scan failed (err=%d)\n",
			   n_orphan);
	} else if (n_orphan > 0) {
		seq_puts(m, "\n--- Kallsyms Orphan Modules ---\n");
		seq_puts(m, "(modules whose symbols remain in kallsyms but are not in /proc/modules)\n");
		seq_puts(m, "These may be rootkits that tampered with both modules list AND kset.\n\n");
		for (i = 0; i < n_orphan; i++) {
			seq_printf(m, "ORPHAN  %s  (%d symbols)\n",
				   orphans[i].name, orphans[i].sym_count);
		}
	}

	kfree(orphans);

	/* ------------------------------------------------------------------ */
	/* Summary                                                            */
	/* ------------------------------------------------------------------ */

summary:
	if (n_hidden == 0 && n_orphan <= 0)
		seq_puts(m, "\n(no hidden modules detected)\n");
	else
		seq_printf(m, "\n%d hidden module(s) found, %d orphan module(s) found.\n",
			   n_hidden, max(n_orphan, 0));

	seq_puts(m, "\nTo restore: echo 'restore <name>' > /proc/modscan\n");
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
static ssize_t modscan_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	/* "restore " (8) + MODULE_NAME_LEN (56) + NUL */
	char kbuf[8 + MODULE_NAME_LEN];
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

	if (sscanf(kbuf, "restore %55s", modname) != 1) {
		pr_err("modscan: unknown command '%s'\n"
		       "modscan: usage: echo 'restore <name>' > /proc/modscan\n",
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
		pr_err("modscan: '%s' not found in module kset\n", modname);
		return -ENOENT;
	}

	/* Step 2 — re-link under module_mutex */
	if (mutex_lock_killable(modscan_module_mutex))
		return -EINTR;

	if (name_in_modules_list(modname)) {
		mutex_unlock(modscan_module_mutex);
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
	mutex_unlock(modscan_module_mutex);

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
