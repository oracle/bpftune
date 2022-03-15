#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/types.h>

#include "libbpftune.h"

#ifndef BPFTUNE_VERSION
#define BPFTUNE_VERSION  "0.1"
#endif

void *perf_buffer;
int perf_map_fd;

char *bin_name;

static void cleanup(int sig)
{
	bpftune_log(LOG_DEBUG, "cleaning up, got signal %d\n", sig);
	bpftune_perf_buffer_fini(perf_buffer);
}

void fini(void)
{
	struct bpftuner *tuner;

	bpftune_for_each_tuner(tuner)
		bpftuner_fini(tuner);
	bpftune_cgroup_fini();
}

int init(const char *cgroup_dir, const char *library_dir, int page_cnt)
{
	char library_path[512];
	struct dirent *dirent;
	DIR *dir;
	int err;

	err = bpftune_cgroup_init(cgroup_dir);
	if (err)
		return err;

	dir = opendir(library_dir);
	if (!dir) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not open dir '%s': %s\n",
			    library_dir, strerror(-err));
		return err;
	}
	bpftune_log(LOG_DEBUG, "searching %s for plugins...\n", library_dir);
	while ((dirent = readdir(dir)) != NULL) {
		struct bpftuner *tuner;

		if (strstr(dirent->d_name, BPFTUNER_LIB_SUFFIX) == NULL)
			continue;
		snprintf(library_path, sizeof(library_path), "%s/%s",
			 library_dir, dirent->d_name);
		bpftune_log(LOG_DEBUG, "found lib %s, init\n", library_path);
		tuner = bpftuner_init(library_path, perf_map_fd);
		/* individual tuner failure shouldn't prevent progress */
		if (!tuner)
			continue;
		if (perf_map_fd == 0)
			perf_map_fd = tuner->perf_map_fd;
	}

	if (perf_map_fd > 0) {
		perf_buffer = bpftune_perf_buffer_init(perf_map_fd, page_cnt,
						       NULL);
		if (!perf_buffer)
			return -1;
	} else {
		bpftune_log(LOG_ERR, "no perf events to watch, exiting.\n");
		return -ENOENT;
	}
	return 0;
}

void do_help(void)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"	OPTIONS := { { -d|--debug} {-D|--daemon}\n"
		"		     { -c|--cgroup_path cgroup_path}\n"
		"		     {-h|--help}}\n"
		"		     { -l|--library_path library_path\n"
		"		     { -V|--version}}\n",
		bin_name);
}

static void do_version(void)
{
	printf("%s v%s\n", bin_name, BPFTUNE_VERSION);
}

static void do_usage(void)
{
	do_help();
	exit(1);
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "cgroup",	required_argument,	NULL,	'c' },
		{ "debug",	no_argument,		NULL,	'd' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "libdir",	required_argument,	NULL,	'l' },
		{ "version",	no_argument,		NULL,	'V' },
		{ 0 }
	};
	char *cgroup_dir = BPFTUNER_CGROUP_DIR;
	char *library_dir = BPFTUNER_LIB_DIR;
	int page_cnt = 8, interval = 100;
	int log_level = LOG_WARNING;
	int err, opt;

	bin_name = argv[0];

	while ((opt = getopt_long(argc, argv, "c:dDhl:V", options, NULL))
		>= 0) {
		switch (opt) {
		case 'c':
			cgroup_dir = optarg;
			break;
		case 'd':
			log_level = LOG_DEBUG;
			break;
		case 'D':
			if (daemon(1, 1)) {
				fprintf(stderr, "cannot daemonize: %s\n",
					strerror(errno));
				return 1;
			}
			break;
		case 'h':
			do_help();
			return 0;
		case 'l':
			library_dir = optarg;
			break;
		case 'V':
			do_version();
			return 0;
		default:
			fprintf(stderr, "unrecognized option '%s'\n",
				argv[optind - 1]);
			do_usage();
		}
	}

	bpftune_set_log(log_level, bpftune_log_stderr);

	if (init(cgroup_dir, library_dir, page_cnt))
		exit(EXIT_FAILURE);

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	err = bpftune_perf_buffer_poll(perf_buffer, interval);

	fini();

	return err;
}
