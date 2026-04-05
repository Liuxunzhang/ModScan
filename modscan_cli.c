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
#include <unistd.h>

#define PROC_PATH   "/proc/modscan"
#define READ_BUF    4096

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s scan              - scan for DKOM-hidden kernel modules\n"
		"  %s restore <name>    - restore a hidden module to the module list\n"
		"\n"
		"The modscan kernel module must be loaded first:\n"
		"  sudo insmod modscan.ko\n",
		prog, prog);
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

	fprintf(stderr, "error: unknown command '%s'\n\n", argv[1]);
	usage(argv[0]);
	return EXIT_FAILURE;
}
