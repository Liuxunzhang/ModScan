/*
 * modscan_cli.c — userspace CLI for the modscan kernel module
 *
 * Communicates with the modscan kernel module via /proc/modscan.
 *
 * Usage:
 *   modscan scan              — list all DKOM-hidden kernel modules
 *   modscan restore <name>    — re-link a hidden module into modules list
 *
 * The kernel module must be loaded first:
 *   sudo insmod modscan.ko
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PROC_PATH   "/proc/modscan"
#define READ_BUF    4096

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s scan                    - scan for hidden kernel modules\n"
		"  %s restore <name>          - restore hidden module by name\n"
		"  %s restore-addr <hexaddr>  - restore hidden module by struct module address\n"
		"  %s repair-force <name>     - aggressive in-kernel state/refcount repair\n"
		"  %s unload <name>           - unload module via delete_module syscall\n"
		"  %s unload-force <name>     - force unload module (O_TRUNC)\n"
		"\n"
		"The modscan kernel module must be loaded first:\n"
		"  sudo insmod modscan.ko\n",
		prog, prog, prog, prog, prog, prog);
	exit(EXIT_FAILURE);
}

static int cmd_scan(void)
{
	char buf[READ_BUF];
	ssize_t n;
	int fd;

	fd = open(PROC_PATH, O_RDONLY);
	if (fd < 0) {
		perror("open " PROC_PATH);
		if (errno == ENOENT)
			fprintf(stderr, "Is the modscan kernel module loaded?\n"
					"  sudo insmod modscan.ko\n");
		return EXIT_FAILURE;
	}

	while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
		buf[n] = '\0';
		fputs(buf, stdout);
	}

	if (n < 0)
		perror("read");

	close(fd);
	return (n < 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int cmd_restore(const char *modname)
{
	/*
	 * Maximum command: "restore " (8) + MODULE_NAME_LEN (56) = 64 bytes.
	 * The kernel's sscanf format is "%55s", so names longer than 55 chars
	 * are rejected; we enforce the same limit here.
	 */
	char cmd[64];
	ssize_t written;
	int fd, len;

	if (strlen(modname) > 55) {
		fprintf(stderr, "error: module name too long (max 55 chars)\n");
		return EXIT_FAILURE;
	}

	len = snprintf(cmd, sizeof(cmd), "restore %s", modname);

	fd = open(PROC_PATH, O_WRONLY);
	if (fd < 0) {
		perror("open " PROC_PATH);
		if (errno == ENOENT)
			fprintf(stderr, "Is the modscan kernel module loaded?\n"
					"  sudo insmod modscan.ko\n");
		return EXIT_FAILURE;
	}

	written = write(fd, cmd, len);
	close(fd);

	if (written < 0) {
		switch (errno) {
		case ENOENT:
			fprintf(stderr,
				"error: module '%s' not found in kset.\n"
				"Check the exact module name with: modscan scan\n",
				modname);
			break;
		case EEXIST:
			fprintf(stderr,
				"info: module '%s' is already visible in lsmod.\n",
				modname);
			break;
		default:
			perror("write");
			break;
		}
		return EXIT_FAILURE;
	}

	printf("Module '%s' restored to modules list.\n", modname);
	printf("Verify with: lsmod | grep %s\n", modname);
	printf("Remove with: sudo rmmod %s\n", modname);
	return EXIT_SUCCESS;
}

static int cmd_restore_addr(const char *raw_addr)
{
	char cmd[64];
	char *end = NULL;
	unsigned long long val;
	ssize_t written;
	int fd, len;

	errno = 0;
	val = strtoull(raw_addr, &end, 16);
	if (errno != 0 || end == raw_addr || *end != '\0' || val == 0ULL) {
		fprintf(stderr,
			"error: invalid address '%s' (expect hex, e.g. 0xffffffffc0395a80)\n",
			raw_addr);
		return EXIT_FAILURE;
	}

	len = snprintf(cmd, sizeof(cmd), "restore-addr %s", raw_addr);
	if (len < 0 || len >= (int)sizeof(cmd)) {
		fprintf(stderr, "error: restore-addr command too long\n");
		return EXIT_FAILURE;
	}

	fd = open(PROC_PATH, O_WRONLY);
	if (fd < 0) {
		perror("open " PROC_PATH);
		if (errno == ENOENT)
			fprintf(stderr, "Is the modscan kernel module loaded?\n"
					"  sudo insmod modscan.ko\n");
		return EXIT_FAILURE;
	}

	written = write(fd, cmd, len);
	close(fd);

	if (written < 0) {
		perror("write");
		return EXIT_FAILURE;
	}

	printf("Module at address '%s' restored to modules list.\n", raw_addr);
	return EXIT_SUCCESS;
}

static int cmd_unload(const char *modname, int force)
{
	int flags = force ? O_TRUNC : 0;

#ifdef SYS_delete_module
	if (syscall(SYS_delete_module, modname, flags) == 0) {
		printf("Module '%s' unloaded successfully.%s\n",
		       modname,
		       force ? " (forced)" : "");
		return EXIT_SUCCESS;
	}
#else
	errno = ENOSYS;
#endif

	switch (errno) {
	case EBUSY:
		fprintf(stderr,
			"error: module '%s' is busy/in use (try unload-force).\n",
			modname);
		break;
	case EAGAIN:
		fprintf(stderr,
			"error: module '%s' temporarily unavailable (state changing).\n",
			modname);
		break;
	case ENOENT:
		fprintf(stderr,
			"error: module '%s' is not currently loaded.\n",
			modname);
		break;
	case ENOSYS:
		fprintf(stderr,
			"error: delete_module syscall unavailable on this platform/toolchain.\n");
		break;
	default:
		perror("delete_module");
		break;
	}

	return EXIT_FAILURE;
}

static int cmd_repair_force(const char *modname)
{
	char cmd[80];
	ssize_t written;
	int fd, len;

	if (strlen(modname) > 55) {
		fprintf(stderr, "error: module name too long (max 55 chars)\n");
		return EXIT_FAILURE;
	}

	len = snprintf(cmd, sizeof(cmd), "repair-force %s", modname);
	if (len < 0 || len >= (int)sizeof(cmd)) {
		fprintf(stderr, "error: repair-force command too long\n");
		return EXIT_FAILURE;
	}

	fd = open(PROC_PATH, O_WRONLY);
	if (fd < 0) {
		perror("open " PROC_PATH);
		if (errno == ENOENT)
			fprintf(stderr, "Is the modscan kernel module loaded?\n"
					"  sudo insmod modscan.ko\n");
		return EXIT_FAILURE;
	}

	written = write(fd, cmd, len);
	close(fd);

	if (written < 0) {
		perror("write");
		return EXIT_FAILURE;
	}

	printf("repair-force sent for module '%s'.\n", modname);
	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	if (strcmp(argv[1], "scan") == 0)
		return cmd_scan();

	if (strcmp(argv[1], "restore") == 0) {
		if (argc < 3) {
			fprintf(stderr, "error: restore requires a module name\n\n");
			usage(argv[0]);
		}
		return cmd_restore(argv[2]);
	}

	if (strcmp(argv[1], "restore-addr") == 0) {
		if (argc < 3) {
			fprintf(stderr, "error: restore-addr requires a hex address\n\n");
			usage(argv[0]);
		}
		return cmd_restore_addr(argv[2]);
	}

	if (strcmp(argv[1], "unload") == 0) {
		if (argc < 3) {
			fprintf(stderr, "error: unload requires a module name\n\n");
			usage(argv[0]);
		}
		return cmd_unload(argv[2], 0);
	}

	if (strcmp(argv[1], "repair-force") == 0) {
		if (argc < 3) {
			fprintf(stderr, "error: repair-force requires a module name\n\n");
			usage(argv[0]);
		}
		return cmd_repair_force(argv[2]);
	}

	if (strcmp(argv[1], "unload-force") == 0) {
		if (argc < 3) {
			fprintf(stderr, "error: unload-force requires a module name\n\n");
			usage(argv[0]);
		}
		return cmd_unload(argv[2], 1);
	}

	fprintf(stderr, "error: unknown command '%s'\n\n", argv[1]);
	usage(argv[0]);
	return EXIT_FAILURE;
}
