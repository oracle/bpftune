/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#define _BSD_SOURCE
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
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/types.h>

#include "libbpftune.h"

#ifndef BPFTUNE_VERSION
#define BPFTUNE_VERSION  "0.1"
#endif

int ringbuf_map_fd;
void *ring_buffer;
bool use_stderr;

char *allowlist[BPFTUNE_MAX_TUNERS];
int nr_allowlist;

char *bin_name;

static void cleanup(int sig)
{
	bpftune_log(LOG_DEBUG, "cleaning up, got signal %d\n", sig);
	bpftune_ring_buffer_fini(ring_buffer);
	if (use_stderr)
		fflush(stderr);
}

void fini(void)
{
	struct bpftuner *tuner;

	bpftune_for_each_tuner(tuner)
		bpftuner_fini(tuner, BPFTUNE_INACTIVE);
	bpftune_cgroup_fini();
}

int init(const char *cgroup_dir, const char *library_dir)
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
		bool allowed = true;

		/* check if tuner is on optional allowlist */
		if (nr_allowlist) {
			int i;

			allowed = false;
			for (i = 0; i < nr_allowlist; i++) {
				if (strcmp(dirent->d_name, allowlist[i]) == 0) {
					allowed = true;
					break;
				}
			}
		}
		if (!allowed) {
			bpftune_log(LOG_DEBUG, "skipping %s as not on allowlist\n",
				    dirent->d_name);
			continue;
		}
					
		if (strstr(dirent->d_name, BPFTUNER_LIB_SUFFIX) == NULL)
			continue;
		snprintf(library_path, sizeof(library_path), "%s/%s",
			 library_dir, dirent->d_name);
		bpftune_log(LOG_DEBUG, "found lib %s, init\n", library_path);
		tuner = bpftuner_init(library_path);
		/* individual tuner failure shouldn't prevent progress */
		if (!tuner)
			continue;
		if (ringbuf_map_fd == 0)
			ringbuf_map_fd = bpftuner_ring_buffer_map_fd(tuner);
	}

	if (ringbuf_map_fd > 0) {
		ring_buffer = bpftune_ring_buffer_init(ringbuf_map_fd, NULL);
		if (!ring_buffer)
			return -1;
	} else {
		bpftune_log(LOG_ERR, "no ringbuf events to watch, exiting.\n");
		return -ENOENT;
	}
	bpftune_netns_init_all();

	return 0;
}

void do_help(void)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"	OPTIONS := { { -a|--allowlist tuner [-a tuner]}\n"
		"		     { -d|--debug} {-D|--daemon}\n"
		"		     { -c|--cgroup_path cgroup_path}\n"
		"		     { -L|--legacy}\n"
		"		     {-h|--help}}\n"
		"		     { -l|--library_path library_path}\n"
		"		     { -s|--stderr}\n"
		"		     { -S|--suppport}\n"
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

void print_support_level(enum bpftune_support_level support_level)
{
	switch (support_level) {
	case BPFTUNE_NONE:
		bpftune_log(LOG_INFO, "bpftune is not supported\n");
		break;
	case BPFTUNE_LEGACY:
		bpftune_log(LOG_INFO, "bpftune works in legacy mode\n");
		break;
	case BPFTUNE_NORMAL:
		bpftune_log(LOG_INFO, "bpftune works fully\n");
		break;
	}
	if (support_level > BPFTUNE_NONE) {
		bpftune_log(LOG_INFO, "bpftune %s per-netns policy (via netns cookie)\n",
			    bpftune_netns_cookie_supported() ?
			    "supports" : "does not support");
	}
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "allowlist",	required_argument,	NULL,	'a' },
		{ "cgroup",	required_argument,	NULL,	'c' },
		{ "debug",	no_argument,		NULL,	'd' },
		{ "legacy",	no_argument,		NULL,	'L' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "libdir",	required_argument,	NULL,	'l' },
		{ "stderr", 	no_argument,		NULL,	's' },
		{ "support",	no_argument,		NULL,	'S' },
		{ "version",	no_argument,		NULL,	'V' },
		{ 0 }
	};
	char *cgroup_dir = BPFTUNER_CGROUP_DIR;
	char *library_dir = BPFTUNER_LIB_DIR;
	enum bpftune_support_level support_level;
	int log_level = LOG_INFO;
	bool is_daemon = false;
	int interval = 100;
	int err, opt;

	bin_name = argv[0];

	while ((opt = getopt_long(argc, argv, "a:c:dDhl:LsSV", options, NULL))
		>= 0) {
		switch (opt) {
		case 'a':
			allowlist[nr_allowlist++] = optarg;
			break;
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
			is_daemon = true;
			break;
		case 'h':
			do_help();
			return 0;
		case 'l':
			library_dir = optarg;
			break;
		case 'L':
			bpftuner_force_bpf_legacy();
			break;
		case 's':
			use_stderr = true;
			break;
		case 'S':
			use_stderr = true;
			support_level = bpftune_bpf_support();
			print_support_level(support_level);
			return support_level > BPFTUNE_NONE ? 0 : 1;
		case 'V':
			do_version();
			return 0;
		default:
			fprintf(stderr, "unrecognized option '%s'\n",
				argv[optind - 1]);
			do_usage();
		}
	}

	bpftune_set_log(log_level, is_daemon || !use_stderr ? bpftune_log_syslog : bpftune_log_stderr);

	support_level = bpftune_bpf_support();
	print_support_level(support_level);
	if (support_level < BPFTUNE_LEGACY) {
		bpftune_log(LOG_ERR, "bpftune is not supported on this system; exiting\n");
		return 1;
	}
	if (init(cgroup_dir, library_dir))
		exit(EXIT_FAILURE);

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	err = bpftune_ring_buffer_poll(ring_buffer, interval);

	fini();

	return err;
}
