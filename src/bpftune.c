/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#define _DEFAULT_SOURCE
#define _POSIX_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/inotify.h>
#include <ftw.h>

#include <bpftune/libbpftune.h>

#ifndef BPFTUNE_VERSION
#define BPFTUNE_VERSION  "0.1"
#endif

int ringbuf_map_fd;
void *ring_buffer;
bool use_stderr;

char *allowlist[BPFTUNE_MAX_TUNERS];
int nr_allowlist;
char *bin_name;

bool exiting;

static void cleanup(int sig)
{
	exiting = true;
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

#define MAX_INOTIFY_EVENTS	32

void *inotify_thread(void *arg)
{
	int inotify_fd, wd, len = 0, i = 0;
	const char *library_dir = arg;
	char library_path[PATH_MAX];
	char buf[sizeof(struct inotify_event) * MAX_INOTIFY_EVENTS];
	struct bpftuner *tuner;

	if (bpftune_cap_add())
		return NULL;
	inotify_fd = inotify_init();
	if (inotify_fd < 0) {
		bpftune_log(BPFTUNE_LOG_LEVEL, "cannot monitor '%s' for changes: %s\n",
			    library_path, strerror(errno));
		bpftune_cap_drop();
		return NULL;
	}
	wd = inotify_add_watch(inotify_fd, library_dir, IN_CREATE | IN_DELETE);

	bpftune_cap_drop();

	while (!exiting) {
		len = read(inotify_fd, buf, sizeof(buf));

		for (i = 0; i < len; i += sizeof(struct inotify_event)) {
			struct inotify_event *event = (struct inotify_event *)&buf[i];

			if (event->mask & IN_ISDIR ||
			    !strstr(event->name, ".so"))
				continue;
			snprintf(library_path, sizeof(library_path), "%s/%s",
				 library_dir, event->name);
			if (event->mask & IN_CREATE) {
				tuner = bpftuner_init(library_path);
				bpftune_log(BPFTUNE_LOG_LEVEL, "added lib %s, init %s\n",
					    library_path,
					    tuner ? "succeeded" : "failed");
				if (!tuner)
					continue;
				if (ringbuf_map_fd == 0)
					ringbuf_map_fd = bpftuner_ring_buffer_map_fd(tuner);
			} else if (event->mask & IN_DELETE) {
				bpftune_for_each_tuner(tuner) {
					if (!strstr(event->name, tuner->name))
						continue;
					bpftune_log(BPFTUNE_LOG_LEVEL, "removed '%s', fini tuner %s\n",
						    library_path, tuner->name);
					bpftuner_fini(tuner, BPFTUNE_MANUAL);
				}
			}
		}
	}
	if (!bpftune_cap_add())
		inotify_rm_watch(inotify_fd, wd);
	bpftune_cap_drop();
	close(inotify_fd);

	return NULL;
}

int init(const char *library_dir)
{
	pthread_attr_t attr = {};
	char library_path[512];
	struct dirent *dirent;
	pthread_t inotify_tid;
	DIR *dir;
	int err;

	dir = opendir(library_dir);
	if (!dir) {
		err = -errno;
		bpftune_log(LOG_DEBUG, "could not open dir '%s': %s\n",
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

	if (pthread_attr_init(&attr) ||
	    pthread_create(&inotify_tid, &attr, inotify_thread, (void *)library_dir))
		bpftune_log(LOG_ERR, "could not create inotify thread: %s\n",
			    strerror(errno));

	if (ringbuf_map_fd > 0) {
		ring_buffer = bpftune_ring_buffer_init(ringbuf_map_fd, NULL);
		if (!ring_buffer)
			return -1;
	} else {
		bpftune_log(BPFTUNE_LOG_LEVEL, "no ringbuf events to watch, exiting.\n");
		return -ENOENT;
	}
	bpftune_netns_init_all();

	return 0;
}

void do_help(void)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS]\n"
		"	OPTIONS := { { -a|--allow tuner}\n"
		"		     { -d|--debug} {-D|--daemon}\n"
		"		     { -c|--cgroup_path cgroup_path}\n"
		"		     { -L|--legacy}\n"
		"		     { -h|--help}}\n"
		"		     { -l|--library_path library_path}\n"
		"		     { -r|--learning_rate learning_rate}\n"
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
		bpftune_log(BPFTUNE_LOG_LEVEL, "bpftune is not supported\n");
		break;
	case BPFTUNE_LEGACY:
		bpftune_log(BPFTUNE_LOG_LEVEL, "bpftune works in legacy mode\n");
		break;
	case BPFTUNE_NORMAL:
		bpftune_log(BPFTUNE_LOG_LEVEL, "bpftune works fully\n");
		break;
	}
	if (support_level > BPFTUNE_NONE) {
		bpftune_log(BPFTUNE_LOG_LEVEL, "bpftune %s per-netns policy (via netns cookie)\n",
			    bpftune_netns_cookie_supported() ?
			    "supports" : "does not support");
	}
}

int main(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "allow",	required_argument,	NULL,	'a' },
		{ "cgroup",	required_argument,	NULL,	'c' },
		{ "daemon", 	no_argument,		NULL,	'D' },
		{ "debug",	no_argument,		NULL,	'd' },
		{ "legacy",	no_argument,		NULL,	'L' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "libdir",	required_argument,	NULL,	'l' },
		{ "learning_rate", required_argument,	NULL,	'r' },
		{ "stderr", 	no_argument,		NULL,	's' },
		{ "support",	no_argument,		NULL,	'S' },
		{ "version",	no_argument,		NULL,	'V' },
		{ 0 }
	};
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char *cgroup_dir = BPFTUNER_CGROUP_DIR;
	char *library_dir = BPFTUNER_LOCAL_LIB_DIR;
	enum bpftune_support_level support_level;
	unsigned short rate = BPFTUNE_DELTA_MAX;
	int log_level = BPFTUNE_LOG_LEVEL;
	bool support_only = false;
	struct sigaction sa = {};
	int interval = 100;
	int err, opt;

	bin_name = argv[0];

	while ((opt = getopt_long(argc, argv, "a:c:dDhl:Lr:sSV", options, NULL))
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
		case 'r':
			rate = atoi(optarg);
			if (rate > BPFTUNE_DELTA_MAX) {
				fprintf(stderr, "values %d-%d are supported\n",
					BPFTUNE_DELTA_MIN, BPFTUNE_DELTA_MAX);
				return 1;
			}
			break;
		case 's':
			use_stderr = true;
			break;
		case 'S':
			use_stderr = true;
			support_only = true;
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

	bpftune_set_log(log_level, use_stderr ? bpftune_log_stderr : bpftune_log_syslog);

	bpftune_set_learning_rate(rate);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		err = -errno;
		bpftune_log(BPFTUNE_LOG_LEVEL, "cannot unlock memory limit: %s.\nAre you running with CAP_SYS_ADMIN/via sudo/as root?\n",
			    strerror(-err));
		return err;
	}

	if (bpftune_cap_add())
		exit(EXIT_FAILURE);

	/* need to setup cgroup prior to probe as probe program uses sysctl */
	err = mkdir(BPFTUNE_RUN_DIR, 0700);
	if (err && errno != EEXIST) {
		bpftune_log(BPFTUNE_LOG_LEVEL, "could not create '%s': %s\n",
			    BPFTUNE_RUN_DIR, strerror(errno));
		exit(EXIT_FAILURE);
	}	
	err = bpftune_cgroup_init(cgroup_dir);
	if (err)
		exit(EXIT_FAILURE);

	support_level = bpftune_bpf_support();
	print_support_level(support_level);
	if (support_level < BPFTUNE_LEGACY) {
		bpftune_log(BPFTUNE_LOG_LEVEL, "bpftune is not supported on this system; exiting\n");
		return 1;
	}
	if (support_only)
		return 0;

	bpftune_cap_drop();

	if (init(BPFTUNER_LIB_DIR)) {
		bpftune_log(LOG_ERR, "could not initialize tuners in '%s'\n",
			    BPFTUNER_LIB_DIR);
		exit(EXIT_FAILURE);
	}
	/* optional dir absence will not trigger failure */
	if (library_dir)
		init(library_dir);

	sa.sa_handler = cleanup;
	if (sigaction(SIGINT, &sa, NULL) == -1 ||
	    sigaction(SIGTERM, &sa, NULL) == -1) {
		err = -errno;
		bpftune_log(LOG_ERR, "signal handling failure: %s\n",
			    strerror(-err));
	} else {
		err = bpftune_ring_buffer_poll(ring_buffer, interval);
	}

	fini();

	return err;
}
