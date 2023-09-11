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

#define _GNU_SOURCE  
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sched.h>
#include <mntent.h>
#include <sys/capability.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

unsigned short bpftune_learning_rate;

#include <bpftune/libbpftune.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "probe.skel.h"
#include "probe.skel.legacy.h"
#include "probe.skel.nobtf.h"

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif

void *bpftune_log_ctx;

int bpftune_loglevel = BPFTUNE_LOG_LEVEL;

struct ring_buffer *ring_buffer;
int ring_buffer_map_fd;
int netns_map_fd;

int bpftune_log_level(void)
{
	return bpftune_loglevel;
}

void bpftune_log_stderr(__attribute__((unused)) void *ctx,
			__attribute__((unused)) int level,
			const char *fmt, va_list args)
{
	if (level <= bpftune_loglevel) {
		fprintf(stderr, "bpftune: ");
		vfprintf(stderr, fmt, args);
	}
}

#define BPFTUNE_LOG_MAX		512

void bpftune_log_syslog(__attribute__((unused)) void *ctx, int level,
			const char *fmt, va_list args)
{
	char buf[BPFTUNE_LOG_MAX];
	int buflen;

	buflen = vsnprintf(buf, sizeof(buf), fmt, args);
	if (buflen > 0)
		syslog(level, buf, buflen + 1);
}

void (*bpftune_logfn)(void *ctx, int level, const char *fmt, va_list args) =
	bpftune_log_stderr;

static void __bpftune_log(int level, const char *fmt, va_list args)
{
		bpftune_logfn(bpftune_log_ctx, level, fmt, args);
}

void bpftune_log(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bpftune_logfn(bpftune_log_ctx, level, fmt, args);
	va_end(args);
}

static int bpftune_libbpf_nolog(__attribute__((unused))enum libbpf_print_level l,
				__attribute__((unused))const char *format,
				__attribute__((unused))va_list args)
{
	return 0;
}

static int bpftune_libbpf_log(enum libbpf_print_level l, const char *format,
			      va_list args)
{
	int level;

	switch (l) {
	case LIBBPF_WARN:
		level = LOG_WARNING;
		break;
	case LIBBPF_INFO:
		level = LOG_INFO;
		break;
	case LIBBPF_DEBUG:
		level = LOG_DEBUG;
		break;
	default:
		return 0;
	}
	if (bpftune_loglevel < level)
		return 0;
	
	__bpftune_log(LOG_DEBUG, format, args);
        return 0;
}

void bpftune_set_bpf_log(bool log)
{
	libbpf_set_print((log || bpftune_loglevel >= LOG_DEBUG) ?
			 bpftune_libbpf_log : bpftune_libbpf_nolog);
}

void bpftune_set_log(int level,
		     void (*logfn)(void *ctx, int level, const char *fmt,
				   va_list args))
{
	if (logfn)
		bpftune_logfn = logfn;
	bpftune_loglevel = level;
	if (logfn == bpftune_log_syslog) {
		setlogmask(LOG_UPTO(level));
                openlog("bpftune", LOG_NDELAY | LOG_PID, LOG_DAEMON);
	}
	bpftune_set_bpf_log(true);
}

static void bpftune_log_bpf(int level, int err, const char *fmt)
{
	char errbuf[256];

	(void) libbpf_strerror(err, errbuf, sizeof(errbuf));
	bpftune_log(level, fmt, errbuf);
}

void bpftune_log_bpf_err(int err, const char *fmt)
{
	bpftune_log_bpf(LOG_ERR, err, fmt);
}

static const cap_value_t cap_vector[] = {
						CAP_SYS_ADMIN,
						CAP_NET_ADMIN,
						CAP_SYS_CHROOT,
						CAP_SYS_MODULE,
						CAP_SYSLOG
};

static cap_t cap_dropped, cap_off, cap_on;
static pthread_key_t cap_key;
static pthread_once_t cap_once = PTHREAD_ONCE_INIT;

/* capabilities are thread-specific, maintain a count for nested calls
 * so we only drop caps when it reaches zero.
 */
static int *cap_count(void)
{
	int *count = pthread_getspecific(cap_key);
	if (count)
		return count;
	count = calloc(1, sizeof(int));
	pthread_setspecific(cap_key, count);
	return count;
}

static void bpftune_cap_init(void)
{
	int err = pthread_key_create(&cap_key, NULL);

	if (err)
		bpftune_log(LOG_ERR, "could not create cap key: %s\n",
			    strerror(err));
	cap_dropped = cap_init();
	cap_off = cap_dup(cap_dropped);
	cap_set_flag(cap_off, CAP_PERMITTED, ARRAY_SIZE(cap_vector),cap_vector,
		     CAP_SET);

			
	cap_on = cap_dup(cap_off);
	cap_set_flag(cap_on, CAP_EFFECTIVE, ARRAY_SIZE(cap_vector), cap_vector,
		     CAP_SET);
}

int bpftune_cap_add(void)
{
	int ret = 0;
	int *count;

	(void) pthread_once(&cap_once, bpftune_cap_init);

	count = cap_count();
	(*count)++;
	bpftune_log(LOG_DEBUG, "set caps (count %d)\n", *count);
	if (*count == 1) {
		if (cap_set_proc(cap_on) != 0) {
			ret = -errno;
			bpftune_log(LOG_ERR, "could not set caps: %s\n",
				    strerror(errno));
		}
	}

	return ret;
}


void bpftune_cap_drop(void)
{
	int *count;

	(void) pthread_once(&cap_once, bpftune_cap_init);

	count = cap_count();
	if (*count > 0)
		(*count)--;
	bpftune_log(LOG_DEBUG, "drop caps (count %d)\n", *count);
	if (*count == 0) {
		if (cap_set_proc(cap_off) != 0)
			bpftune_log(LOG_ERR, "could not drop caps: %s\n",
				    strerror(errno));
	}
}

static char bpftune_cgroup_path[PATH_MAX];
static int __bpftune_cgroup_fd;

int bpftune_cgroup_init(const char *cgroup_path)
{
	int err = 0;

	err = bpftune_cap_add();
	if (err)
		return err;
	strncpy(bpftune_cgroup_path, cgroup_path, sizeof(bpftune_cgroup_path));
	__bpftune_cgroup_fd = open(cgroup_path, O_RDONLY);
	if (__bpftune_cgroup_fd < 0) {
		if (mkdir(cgroup_path, 0777)) {
			err = -errno;
			bpftune_log(LOG_ERR, "couldnt create cgroup dir '%s': %s\n",
				    cgroup_path, strerror(-err));
			goto out;
		}
		close(__bpftune_cgroup_fd);
	}
	if (mount("none" , cgroup_path, "cgroup2", 0, NULL)) {
		err = -errno;
		if (err != -EEXIST && err != -EBUSY) {
			bpftune_log(LOG_ERR, "couldnt mount cgroup2 for '%s': %s\n",
				    cgroup_path, strerror(-err));
			if (__bpftune_cgroup_fd > 0)
				close(__bpftune_cgroup_fd);
			goto out;
		}
	}
	if (__bpftune_cgroup_fd < 0)
		__bpftune_cgroup_fd = open(cgroup_path, O_RDONLY);
	if (__bpftune_cgroup_fd < 0) {
		/* we mounted above, unmount here. */
		if (err == 0)
			umount(cgroup_path);
		err = -errno;
		bpftune_log(LOG_ERR, "cannot open cgroup dir '%s': %s\n",
			    cgroup_path, strerror(-err));
	} else {
		err = 0;
	}
out:
	bpftune_cap_drop();
	return err;
}

const char *bpftune_cgroup_name(void)
{
	return bpftune_cgroup_path;
}

int bpftune_cgroup_fd(void)
{
	return __bpftune_cgroup_fd;
}

void bpftune_cgroup_fini(void)
{
	if (__bpftune_cgroup_fd)
		close(__bpftune_cgroup_fd);
}

int bpftuner_cgroup_attach(struct bpftuner *tuner, const char *prog_name,
			   enum bpf_attach_type attach_type)
{
	int prog_fd, cgroup_fd, err = 0;
	struct bpf_program *prog;
	const char *cgroup_dir;

	/* if cgroup prog is not in current strategy prog list, skip attach */
	if (!bpftuner_bpf_prog_in_strategy(tuner, prog_name))
		return 0;

	err = bpftune_cap_add();
	if (err)
		return err;
	
	/* attach to root cgroup */
	cgroup_dir = bpftune_cgroup_name();

	if (!cgroup_dir) {
		bpftune_log(LOG_ERR, "cannot get cgroup_dir\n");
		err = 1;
		goto out;
	}
	cgroup_fd = bpftune_cgroup_fd();
	prog = bpf_object__find_program_by_name(tuner->obj, prog_name);
	if (!prog) {
		bpftune_log(LOG_ERR, "no prog '%s'\n", prog_name);
		err = -EINVAL;
		goto out;
	}
	prog_fd = bpf_program__fd(prog);

	if (bpf_prog_attach(prog_fd, cgroup_fd, attach_type,
			    BPF_F_ALLOW_MULTI)) {
		err = -errno;
		bpftune_log(LOG_ERR, "cannot attach '%s' to cgroup '%s': %s\n",
			    prog_name, cgroup_dir, strerror(-err));
	}
out:
	bpftune_cap_drop();

	return err;
}

void bpftuner_cgroup_detach(struct bpftuner *tuner, const char *prog_name,
			   enum bpf_attach_type attach_type)
{
	int prog_fd, cgroup_fd, err = 0;
	struct bpf_program *prog;

	/* if cgroup prog is not in current strategy prog list, skip attach */
	if (!bpftuner_bpf_prog_in_strategy(tuner, prog_name))
		return;

	err = bpftune_cap_add();
	if (err)
		return;
	prog = bpf_object__find_program_by_name(tuner->obj, prog_name);
	if (prog) {
		prog_fd = bpf_program__fd(prog);
		cgroup_fd = bpftune_cgroup_fd();

		if (bpf_prog_detach2(prog_fd, cgroup_fd, attach_type)) {
                        err = -errno;
                        bpftune_log(LOG_ERR, "error detaching prog fd %d, cgroup fd %d: %s\n",
                                prog_fd, cgroup_fd, strerror(-err));
                }
        } else {
		bpftune_log(LOG_ERR, "bpftuner_cgroup_detach: could not find prog '%s'\n",
			    prog_name);
	}
	bpftune_cap_drop();
}

static bool netns_cookie_supported;

bool bpftune_netns_cookie_supported(void)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	unsigned long netns_cookie;
	int ret = 0;

	if (s < 0) {
		bpftune_log(LOG_ERR, "could not open socket: %s\n",
			   strerror(errno));
		return false;
	} else {
		socklen_t cookie_sz = sizeof(netns_cookie);

		ret = getsockopt(s, SOL_SOCKET, SO_NETNS_COOKIE, &netns_cookie,
				 &cookie_sz);
		close(s);
		if (ret < 0) {
			bpftune_log(LOG_DEBUG, "netns cookie not supported, cannot monitor per-netns events\n");
			return false;
		}
        }
	return true;
}

enum bpftune_support_level support_level = BPFTUNE_SUPPORT_NONE;
enum bpftune_support_level force_support_level = BPFTUNE_SUPPORT_NONE;

void bpftune_force_bpf_support(enum bpftune_support_level level)
{
	force_support_level = level;
}

enum bpftune_support_level bpftune_bpf_support(void)
{
	bool ret;
	int err;
	struct probe_bpf *probe_bpf = NULL;
	struct probe_bpf_legacy *probe_bpf_legacy = NULL;
	struct probe_bpf_nobtf *probe_bpf_nobtf = NULL;

	if (support_level > BPFTUNE_SUPPORT_NONE)
		goto done;

	err = bpftune_cap_add();
	if (err)
		return BPFTUNE_SUPPORT_NONE;
	/* disable bpf logging to avoid spurious errors */
	bpftune_set_bpf_log(false);

	probe_bpf = probe_bpf__open_and_load();
	support_level = BPFTUNE_SUPPORT_LEGACY;
	err = libbpf_get_error(probe_bpf);
	if (!err) {
		if (!probe_bpf__attach(probe_bpf))
			support_level = BPFTUNE_SUPPORT_NORMAL;
	}

	if (support_level == BPFTUNE_SUPPORT_LEGACY) {
		bpftune_log(LOG_DEBUG, "full bpftune support not available: %s\n",
			    strerror(err));
		probe_bpf_legacy = probe_bpf_legacy__open_and_load();		
		err = libbpf_get_error(probe_bpf_legacy);
		if (!err && (err = probe_bpf_legacy__attach(probe_bpf_legacy)) == 0) {
			support_level = BPFTUNE_SUPPORT_LEGACY;
		} else {	
			bpftune_log(LOG_DEBUG, "legacy bpftune support not available: %s\n",
				    strerror(err));
			probe_bpf_nobtf = probe_bpf_nobtf__open_and_load();
			err = libbpf_get_error(probe_bpf_nobtf);
			if (err) {
				support_level = BPFTUNE_SUPPORT_NONE;
				bpftune_log(LOG_DEBUG, "no-BTF bpftune support not available (load): %s\n",
				    strerror(err));
			} else {
				err = probe_bpf_nobtf__attach(probe_bpf_nobtf);
				if (!err) {
					support_level = BPFTUNE_SUPPORT_NOBTF;
				} else {
					support_level = BPFTUNE_SUPPORT_NONE;
					bpftune_log(LOG_DEBUG, "no-BTF bpftune support not available (attach): %s\n",
						    strerror(err));
				}
			}
		}
	}
	probe_bpf__destroy(probe_bpf);
	if (probe_bpf_legacy)
		probe_bpf_legacy__destroy(probe_bpf_legacy);
	if (probe_bpf_nobtf)
		probe_bpf_nobtf__destroy(probe_bpf_nobtf);

	ret = bpftune_netns_cookie_supported();
	if (!ret)
		bpftune_log(LOG_DEBUG, "netns cookie not supported\n");

	bpftune_set_bpf_log(true);
	bpftune_cap_drop();

done:
	if (force_support_level && force_support_level <= support_level)
		return force_support_level;
	return support_level;
}

/* called with caps set */
static int bpftuner_map_reuse(const char *name, struct bpf_map *map,
			      int fd, int *tuner_fdp)
{
	int err = 0;

	if (fd > 0) {
		bpftune_log(LOG_DEBUG, "reusing %s fd %d\n", name, fd);
		err = bpf_map__reuse_fd(map, fd);
		if (err < 0) {
			bpftune_log_bpf_err(err, "could not reuse fd: %s\n");
		} else {
			*tuner_fdp = fd;
		}
	}
	return err;
}

/* called with caps set */
static void bpftuner_map_init(struct bpftuner *tuner, const char *name,
			      void **mapp, int *fdp, int *tuner_fdp)
{
	struct bpf_map *m;

	if (*fdp > 0)
		return;

	m = bpf_object__find_map_by_name(*tuner->skeleton->obj, name);
	if (m) {
		*mapp = m;

		/* dup fd, because we do not want map to go away if tuner
		 * does.
		 */
		*fdp = dup(bpf_map__fd(m));
		if (*fdp < 0) {
			bpftune_log(LOG_ERR, "could not get pin: %s\n",
					    strerror(errno));
		} else {
			bpftune_log(LOG_DEBUG, "got %s map fd %d\n",
				    name, *fdp);
			*tuner_fdp = bpf_map__fd(m);
		}
	}
}

int __bpftuner_bpf_load(struct bpftuner *tuner, const char **optionals)
{
	int err = 0;

	err = bpftune_cap_add();

	if (err)
		return err;

	if (bpftuner_map_reuse("ring_buffer", tuner->ring_buffer_map,
			       ring_buffer_map_fd, &tuner->ring_buffer_map_fd) ||
	    bpftuner_map_reuse("netns_map", tuner->netns_map,
			       netns_map_fd, &tuner->netns_map_fd)) {
		err = -1;
		goto out;
	}

	if (optionals) {
		int i;

		for (i = 0; optionals[i] != NULL; i++) {
			struct bpf_program *prog;

			bpftune_log(LOG_DEBUG, "looking for optional prog '%s'\n",
				    optionals[i]);
			prog = bpf_object__find_program_by_name(tuner->obj,
								optionals[i]);
			if (prog) {
				bpftune_log(LOG_DEBUG, "marking '%s' as optional\n",
					    optionals[i]);
				bpf_program__set_autoload(prog, false);
			}
		}
	}
	err = bpf_object__load_skeleton(tuner->skeleton);
	if (err) {
		bpftune_log_bpf_err(err, "could not load skeleton: %s\n");
		goto out;
	}

	bpftuner_map_init(tuner, "ring_buffer_map", &tuner->ring_buffer_map,
			  &ring_buffer_map_fd, &tuner->ring_buffer_map_fd);
	bpftuner_map_init(tuner, "netns_map", &tuner->netns_map,
			  &netns_map_fd, &tuner->netns_map_fd);
out:
	bpftune_cap_drop();
	return err;
}

int __bpftuner_bpf_attach(struct bpftuner *tuner)
{
	int err;

	err = bpftune_cap_add();
	if (err)
		return err;
	err = bpf_object__attach_skeleton(tuner->skeleton);
	if (err) {
		bpftune_log_bpf_err(err, "could not attach skeleton: %s\n");
	} else {
		tuner->ring_buffer_map_fd = bpf_map__fd(tuner->ring_buffer_map);
	}
	bpftune_cap_drop();
	return err;
}

static unsigned int bpftune_num_tuners;

void bpftuner_bpf_fini(struct bpftuner *tuner)
{
	if (bpftune_cap_add())
		return;
	bpf_object__destroy_skeleton(tuner->skeleton);
	free(tuner->skel);
	if (bpftune_num_tuners == 0) {
		if (ring_buffer_map_fd > 0)
			close(ring_buffer_map_fd);
		if (netns_map_fd > 0)
			close(netns_map_fd);
		ring_buffer_map_fd = netns_map_fd = 0;
	}
	bpftune_cap_drop();
}

static struct bpftuner *bpftune_tuners[BPFTUNE_MAX_TUNERS];

/* add a tuner to the list of tuners, or replace existing inactive tuner.
 * If successful, call init().
 */
struct bpftuner *bpftuner_init(const char *path)
{
	struct bpftuner *tuner = NULL;
	int err, retries;

	tuner = calloc(1, sizeof(*tuner));
	if (!tuner) {
		bpftune_log(LOG_ERR, "could not allocate tuner\n");
		return NULL;
	}
	tuner->name = path;

	bpftune_cap_add();
	/* if file appears via inotify we may get "file too short" errors;
	 * retry a few times to avoid this.
	 */
	for (retries = 0; retries < 5; retries++) {
		tuner->handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
		if (tuner->handle)
			break;
		usleep(1000);
	}
	bpftune_cap_drop();
	if (!tuner->handle) {
		bpftune_log(LOG_ERR,
			    "could not dlopen '%s' after %d retries: %s\n",
			    path, retries, dlerror());
		free(tuner);
		return NULL;
	}
	/* If we have a ringbuf fd from any tuner, use its fd to be re-used
 	 * for other ringbuf maps (so we can use the same ring buffer for all
 	 * BPF events.
 	 */
	tuner->ring_buffer_map_fd = ring_buffer_map_fd;
	tuner->init = dlsym(tuner->handle, "init");
	tuner->fini = dlsym(tuner->handle, "fini");
	tuner->event_handler = dlsym(tuner->handle, "event_handler");
	if (!tuner->init || !tuner->fini || !tuner->event_handler) {	
		bpftune_log(LOG_ERR, "missing definitions in '%s': need 'init', 'fini' and 'event_handler'\n",
			    path);
		dlclose(tuner->handle);
		free(tuner);
		return NULL;
	}
	bpftune_log(LOG_DEBUG, "calling init for '%s\n", path);
	err = tuner->init(tuner);
	if (err) {
		dlclose(tuner->handle);
		bpftune_log(LOG_ERR, "error initializing '%s: %s\n",
			    path, strerror(-err));
		free(tuner);
		return NULL;
	}
	tuner->id = bpftune_num_tuners;
	tuner->state = BPFTUNE_ACTIVE;
	bpftune_tuners[bpftune_num_tuners++] = tuner;
	bpftune_log(LOG_DEBUG, "sucessfully initialized tuner %s[%d]\n",
		    tuner->name, tuner->id);
	return tuner;
}

static unsigned long global_netns_cookie;

static void bpftuner_scenario_log(struct bpftuner *tuner, unsigned int tunable,
				  unsigned int scenario, int netns_fd,
				  bool summary,
				  const char *fmt, va_list args);

void bpftuner_fini(struct bpftuner *tuner, enum bpftune_state state)
{
	unsigned int i, j;

	if (!tuner || tuner->state != BPFTUNE_ACTIVE)
		return;

	bpftune_log(LOG_DEBUG, "cleaning up tuner %s with %d tunables, %d scenarios\n",
		    tuner->name, tuner->num_tunables, tuner->num_scenarios);
	if (tuner->fini)
		tuner->fini(tuner);
	/* report summary of events for tuner */
	for (i = 0; i < tuner->num_tunables; i++) {
		for (j = 0; j < tuner->num_scenarios; j++) {
			va_list args;
			bpftune_log(LOG_DEBUG, "checking scenarios for tuner %d, scenario %d\n",
				    i, j);
			bpftuner_scenario_log(tuner, i, j, 0, true, NULL, args);
			bpftuner_scenario_log(tuner, i, j, 1, true, NULL, args);
		}
	}
	tuner->state = state;
}

struct bpftuner *bpftune_tuner(unsigned int index)
{
	if (index < bpftune_num_tuners)
		return bpftune_tuners[index];
	return NULL;
}

unsigned int bpftune_tuner_num(void)
{
	return bpftune_num_tuners;
}

void bpftune_set_learning_rate(unsigned short rate)
{
	bpftune_learning_rate = rate;
}

static int bpftune_ringbuf_event_read(void *ctx, void *data, size_t size)
{
	struct bpftune_event *event = data;
	struct bpftuner *tuner;

	if (size < sizeof(*event)) {
		bpftune_log(LOG_ERR, "unexpected size event %d\n", size);
		return 0;
	}
	if (event->tuner_id > BPFTUNE_MAX_TUNERS) {
		bpftune_log(LOG_ERR, "invalid tuner id %d\n", event->tuner_id);
		return 0;
	}
	tuner = bpftune_tuner(event->tuner_id);
	if (!tuner) {
		bpftune_log(LOG_ERR, "no tuner for id %d\n", event->tuner_id);
		return 0;
	}
	bpftune_log(LOG_DEBUG,
		    "event scenario [%d] for tuner %s[%d] netns %ld (%s)\n",
		    event->scenario_id, tuner->name, tuner->id,
		    event->netns_cookie,
		    event->netns_cookie && event->netns_cookie != global_netns_cookie ?
		    "non-global netns" : "global netns");
	tuner->event_handler(tuner, event, ctx);

	return 0;
}

int bpftuner_ring_buffer_map_fd(struct bpftuner *tuner)
{
	return tuner->ring_buffer_map_fd;
}

void *bpftune_ring_buffer_init(int ring_buffer_map_fd, void *ctx)
{
	struct ring_buffer *rb;
	int err;

	bpftune_log(LOG_DEBUG, "calling ring_buffer__new, ringbuf_map_fd %d\n",
		    ring_buffer_map_fd);
	err = bpftune_cap_add();
	if (err)
		return NULL;
	rb = ring_buffer__new(ring_buffer_map_fd, bpftune_ringbuf_event_read, ctx, NULL);
	err = libbpf_get_error(rb);
	if (err) {
		bpftune_log_bpf_err(err, "couldnt create ring buffer: %s\n");
		rb = NULL;
	}
	bpftune_cap_drop();
	return rb;
}

static int ring_buffer_done;

int bpftune_ring_buffer_poll(void *ring_buffer, int interval)
{
	struct ring_buffer *rb = ring_buffer;
	int err;

	while (!ring_buffer_done) {
		err = ring_buffer__poll(rb, interval);
		if (err < 0) {
			/* -EINTR means we got signal; don't report as error. */
			bpftune_log_bpf(err == -EINTR ? LOG_DEBUG : LOG_ERR,
					err, "ring_buffer__poll: %s\n");
			/* signals we have not masked will fini the ring buffer
			 * so do not exit for -EINTR.
			 */
			if (err != -EINTR)
				break;
		}
	}
	ring_buffer__free(rb);
	return 0;
}

void bpftune_ring_buffer_fini(__attribute__((unused)) void *ring_buffer)
{
	ring_buffer_done = true;
}


#define BPFTUNE_PROC_SYS	"/proc/sys/"
void bpftune_sysctl_name_to_path(const char *name, char *path, size_t path_sz)
{
	size_t i;

	snprintf(path, path_sz, BPFTUNE_PROC_SYS "%s", name);
	for (i = 0; i < path_sz && path[i] != 0; i++)
		if (path[i] == '.')
			path[i] = '/';
}

int bpftune_sysctl_read(int netns_fd, const char *name, long *values)
{
	int i, orig_netns_fd = 0, num_values = 0;
	char path[PATH_MAX];
	int err = 0;	
	FILE *fp;

	err = bpftune_cap_add();
	if (err)
		return err;

	bpftune_sysctl_name_to_path(name, path, sizeof(path));

	err = bpftune_netns_set(netns_fd, &orig_netns_fd);
	if (err < 0)
		goto out_unset;

	fp = fopen(path, "r");
	if (!fp) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not open %s (netns fd %d) for reading: %s\n",
			    path, netns_fd, strerror(-err));
		goto out;
	}
	num_values = fscanf(fp, "%ld %ld %ld",
			    &values[0], &values[1], &values[2]);
	if (num_values == 0)
		err = -ENOENT;
	else if (num_values < 0)
		err = -errno;
	fclose(fp);

	if (err) {
		bpftune_log(LOG_ERR, "could not read from %s: %s\n", path,
			    strerror(-err));
		goto out;
	}

	for (i = 0; i < num_values; i++) {
		bpftune_log(LOG_DEBUG, "Read %s[%d] = %ld\n",
			    name, i, values[i]);
	}

out:
	bpftune_netns_set(orig_netns_fd, NULL);
out_unset:
	bpftune_cap_drop();
	return err ? err : num_values;
}

int bpftune_sysctl_write(int netns_fd, const char *name, __u8 num_values, long *values)
{
	long old_values[BPFTUNE_MAX_VALUES] = {};
	int i, err = 0, orig_netns_fd = 0;
	int old_num_values;
	char path[PATH_MAX];
	FILE *fp;

	bpftune_sysctl_name_to_path(name, path, sizeof(path));

	bpftune_log(LOG_DEBUG, "writing sysctl '%s' for netns_fd %d\n",
		    path, netns_fd);

	err = bpftune_cap_add();
	if (err)
		return err;
	err = bpftune_netns_set(netns_fd, &orig_netns_fd);
	if (err < 0)
		goto out_unset;

	/* If value is already set to val, do nothing. */
	old_num_values = bpftune_sysctl_read(0, name, old_values);
	if (old_num_values < 0) {
		err = old_num_values;
		goto out;
	}
	if (num_values == old_num_values) {
		for (i = 0; i < num_values; i++) {
			if (old_values[i] != values[i])
				break;
		}
		if (i == num_values)
			goto out;
	}
        fp = fopen(path, "w");
        if (!fp) {
                err = -errno;
                bpftune_log(LOG_DEBUG, "could not open %s for writing: %s\n",
			    path, strerror(-err));
		goto out;
        }

	for (i = 0; i < num_values; i++)
		fprintf(fp, "%ld ", values[i]);
        fclose(fp);

	for (i = 0; i < num_values; i++) {
		bpftune_log(LOG_DEBUG, "Wrote %s[%d] = %ld\n",
			    name, i, values[i]);
	}
out:
	bpftune_netns_set(orig_netns_fd, NULL);
out_unset:
	bpftune_cap_drop();
        return err;
}

int bpftuner_tunables_init(struct bpftuner *tuner, unsigned int num_descs,
			   struct bpftunable_desc *descs,
			   unsigned int num_scenarios,
			   struct bpftunable_scenario *scenarios)
{
	unsigned int i;

	tuner->scenarios = scenarios;
	tuner->num_scenarios = num_scenarios;
	tuner->tunables = calloc(num_descs, sizeof(struct bpftunable));
	if (!tuner->tunables) {
		bpftune_log(LOG_DEBUG, "no memory to alloc tunables for %s\n",
			    tuner->name);
		return -ENOMEM;
	}
	tuner->num_tunables = num_descs;
	for (i = 0; i < num_descs; i++) {
		int num_values;

		bpftune_log(LOG_DEBUG, "handling desc %ld/%ld\n", i, num_descs);
		memcpy(&tuner->tunables[i].desc, &descs[i], sizeof(*descs));

		if (descs[i].type != BPFTUNABLE_SYSCTL)
			continue;
		num_values = bpftune_sysctl_read(0, descs[i].name,
				tuner->tunables[i].current_values);
		if (num_values < 0) {
			if (descs[i].flags & BPFTUNABLE_OPTIONAL) {
				bpftune_log(LOG_DEBUG, "error reading optional tunable '%s': %s\n",
					    descs[i].name, strerror(-num_values));
				continue;
			}
			bpftune_log(LOG_ERR, "error reading tunable '%s': %s\n",
				    descs[i].name, strerror(-num_values));
			return num_values;
		}
		if (num_values != descs[i].num_values) {
			bpftune_log(LOG_ERR, "error reading tunable '%s'; expected %d values, got %d\n",
				    descs[i].num_values, num_values);
			return -EINVAL;
		}
		memcpy(tuner->tunables[i].initial_values,
		       tuner->tunables[i].current_values,
		       sizeof(tuner->tunables[i].initial_values));
	}

	return 0;
}

struct bpftunable *bpftuner_tunable(struct bpftuner *tuner, unsigned int index)
{
	if (index < tuner->num_tunables)
		return &tuner->tunables[index];
	return NULL;
}

static void __bpftuner_tunable_stats_update(struct bpftunable *tunable,
				   unsigned int scenario, bool global_ns,
				   unsigned long val)
{
	if (global_ns)
		(tunable->stats.global_ns[scenario]) += val;
	else
		(tunable->stats.nonglobal_ns[scenario]) += val;
	bpftune_log(LOG_DEBUG," updated stat for tunable %s, scenario %d: %lu\n",
		    tunable->desc.name, scenario,
		    global_ns ? tunable->stats.global_ns[scenario] :
				tunable->stats.nonglobal_ns[scenario]);

}

void bpftuner_tunable_stats_update(struct bpftuner *tuner,
				   unsigned int tunable,
				   unsigned int scenario, bool global_ns,
				   unsigned long val)
{
	struct bpftunable *t = bpftuner_tunable(tuner, tunable);

	if (!t)
		return;
	__bpftuner_tunable_stats_update(t, scenario, global_ns, val);
}

static void bpftuner_scenario_log(struct bpftuner *tuner, unsigned int tunable,
				  unsigned int scenario, int netns_fd,
				  bool summary,
				  const char *fmt, va_list args)
{
	struct bpftunable *t = bpftuner_tunable(tuner, tunable);
	bool global_ns = netns_fd == 0;

	if (summary) {
		unsigned long count;

		count = global_ns ? t->stats.global_ns[scenario] :
				    t->stats.nonglobal_ns[scenario];
		if (!count)
			return;
		bpftune_log(BPFTUNE_LOG_LEVEL, "Summary: scenario '%s' occurred %ld times for tunable '%s' in %sglobal ns. %s\n",
			    tuner->scenarios[scenario].name, count,
			    t->desc.name,
			    global_ns ? "" : "non-",
			    tuner->scenarios[scenario].description);
		if (t->desc.type == BPFTUNABLE_SYSCTL) {
			char oldvals[PATH_MAX] = { };
			char newvals[PATH_MAX] = { };
			char s[PATH_MAX];
			__u8 i;

			for (i = 0; i < t->desc.num_values; i++) {
				snprintf(s, sizeof(s), "%ld ",
					 t->initial_values[i]);
				strcat(oldvals, s);
				snprintf(s, sizeof(s), "%ld ",
					 t->current_values[i]);
				strcat(newvals, s);
			}
			bpftune_log(BPFTUNE_LOG_LEVEL, "sysctl '%s' changed from (%s) -> (%s)\n",
				    t->desc.name, oldvals, newvals);

			if (tuner->rollback && global_ns) {
				bpftuner_tunable_sysctl_write(tuner,
					tunable,
					scenario,
					0,
					t->desc.num_values,
					t->initial_values,
					"Rolling back sysctl values for '%s' from (%s) to original values (%s)...\n",
					t->desc.name,
					newvals, oldvals);
			}
		}
	} else {
		bpftune_log(BPFTUNE_LOG_LEVEL, "Scenario '%s' occurred for tunable '%s' in %sglobal ns. %s\n",
			    tuner->scenarios[scenario].name,
			    t->desc.name,
			    global_ns ? "" : "non-",
			    tuner->scenarios[scenario].description);
		__bpftune_log(BPFTUNE_LOG_LEVEL, fmt, args);
		__bpftuner_tunable_stats_update(t, scenario, global_ns, 1);
	}
}

int bpftuner_tunable_sysctl_write(struct bpftuner *tuner, unsigned int tunable,
				  unsigned int scenario, unsigned long netns_cookie,
				  __u8 num_values, long *values,
				  const char *fmt, ...)
{
	struct bpftunable *t = bpftuner_tunable(tuner, tunable);
	struct bpftuner_netns *netns;
	int ret = 0, fd = 0;

	if (!t) {
		bpftune_log(LOG_ERR, "no tunable %d for tuner '%s'\n",
			    tunable, tuner->name);
		return -EINVAL;
	}
	netns = bpftuner_netns_from_cookie(tuner->id, netns_cookie);
	if (netns) {
		bpftune_log(LOG_DEBUG, "found netns (cookie %ld); state %d\n",
			    netns_cookie, netns->state);
		if (netns->state >= BPFTUNE_MANUAL) {
			bpftune_log(BPFTUNE_LOG_LEVEL,
				    "Skipping update of '%s' ; tuner '%s' is disabled in netns (cookie %ld)\n",
				    t->desc.name, tuner->name, netns_cookie);
			return 0;
		}
	}

	if (t->desc.flags & BPFTUNABLE_NAMESPACED) {
		fd = bpftuner_netns_fd_from_cookie(tuner, netns_cookie);
		if (fd < 0) {
			bpftune_log(LOG_DEBUG, "could not get netns fd for cookie %ld\n",
				    netns_cookie);
			return 0;
		}
	}

	ret = bpftune_sysctl_write(fd, t->desc.name, num_values, values);
	if (!ret) {
		va_list args;
		__u8 i;

		va_start(args, fmt);
		bpftuner_scenario_log(tuner, tunable, scenario, fd,
				      false, fmt, args);
		va_end(args);

		for (i = 0; i < t->desc.num_values; i++)
			t->current_values[i] = values[i];
	}

	if (fd > 0)
		close(fd);

	return ret;
}

int bpftuner_tunable_update(struct bpftuner *tuner, unsigned int tunable,
			    unsigned int scenario, int netns_fd,
			    const char *fmt, ...)
{
	struct bpftunable *t = bpftuner_tunable(tuner, tunable);
	va_list args;

	if (!t) {
		bpftune_log(LOG_ERR, "no tunable %d for tuner '%s'\n",
			    tunable, tuner->name);
		return -EINVAL;
	}
	va_start(args, fmt);
	bpftuner_scenario_log(tuner, tunable, scenario, netns_fd, false,
			      fmt, args);
	va_end(args);

	return 0;
}

unsigned int bpftuner_num_tunables(struct bpftuner *tuner)
{
	return tuner->num_tunables;
}

void bpftuner_tunables_fini(struct bpftuner *tuner)
{
	tuner->num_tunables = 0;
	free(tuner->tunables);
}

static int bpftune_netns_fd(int netns_pid)
{
	char netns_path[256];
	int netns_fd;
	int err;

	if (netns_pid == 0)
		return 0;
	snprintf(netns_path, sizeof(netns_path), "/proc/%d/ns/net", netns_pid);
	err = bpftune_cap_add();
	if (err)
		return err;
	netns_fd = open(netns_path, O_RDONLY);
	if (netns_fd < 0)
		netns_fd = -errno;
	bpftune_cap_drop();
	return netns_fd;
}

/* sets original netns fd if orig_fd is non-NULL */
int bpftune_netns_set(int new_fd, int *orig_fd)
{
	int fd = 0, err = 0;

	if (!new_fd)
		return 0;

	err = bpftune_cap_add();
	if (err)
		return err;

	if (orig_fd) {
		fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			err = -errno;
			bpftune_log(LOG_ERR,
				    "could not get current netns fd(%d): %s\n",
				    fd, strerror(-err));
			goto out;
		}
	}
	err = setns(new_fd, CLONE_NEWNET);
	if (err < 0) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not %s ns(%d): %s\n",
			    orig_fd ? "set" : "restore",
			    new_fd, strerror(-err));
	}

	if (!err && orig_fd) {
		*orig_fd = fd;
	} else {
		if (fd)
			close(fd);
	}
out:
	bpftune_cap_drop();
	return err;
}

/* get fd, cookie (if non-NULL) from pid, or if pid is 0, use passed in
 * *fd to get cookie.
 */
int bpftune_netns_info(int pid, int *fd, unsigned long *cookie)
{
	unsigned long netns_cookie = 0;
	int netns_fd, orig_netns_fd = 0;
	bool fdnew = true;
	int ret, err;

	if (pid == 0 && fd && *fd > 0) {
		fdnew = false;
		netns_fd = *fd;
	} else {
		netns_fd = bpftune_netns_fd(pid);
		if (netns_fd <= 0)
			return netns_fd;
	}

	err = bpftune_netns_set(netns_fd, &orig_netns_fd);
	if (!err) {
		int s = socket(AF_INET, SOCK_STREAM, 0);

		if (s < 0) {
			ret = -errno;
			bpftune_log(LOG_ERR, "could not open socket in netns: %s\n",
				    strerror(errno)); 
		} else {
			socklen_t cookie_sz = sizeof(netns_cookie);

			ret = getsockopt(s, SOL_SOCKET, SO_NETNS_COOKIE, &netns_cookie,
					 &cookie_sz);
			if (ret < 0) {
				ret = -errno;
				bpftune_log(LOG_DEBUG,
					    "could not get SO_NETNS_COOKIE: %s\n",
					   strerror(-ret));
				/* system may not support SO_NETNS_COOKIE */
			}
			
			close(s);
		}
		bpftune_netns_set(orig_netns_fd, NULL);

		if (ret == 0) {
			if (fdnew && fd)
				*fd = netns_fd;
			if (cookie)
				*cookie = netns_cookie;
		}
	} else {
		bpftune_log(LOG_DEBUG, "setns failed for for fd %d\n",
			    netns_fd);
		ret = -errno;
	}
	if (fdnew && !fd)
		close(netns_fd);
	if (orig_netns_fd > 0)
		close(orig_netns_fd);
	return ret;
}

static int bpftune_netns_find(unsigned long cookie)
{
	unsigned long netns_cookie;
	struct bpftuner *t;
	struct mntent *ent;
        FILE *mounts;
	struct dirent *dirent;
	int ret = -ENOENT;
	DIR *dir;

	if (!netns_cookie_supported || cookie == 0 || (global_netns_cookie && cookie == global_netns_cookie))
		return 0;

	ret = bpftune_cap_add();
	if (ret)
		return ret;

	mounts = setmntent("/proc/mounts", "r");
	if (mounts == NULL) {
		ret = -errno;
		bpftune_log(LOG_ERR, "cannot setmntent() for /proc/mounts\n",
			    strerror(-ret));
		goto out;
	}
	while ((ent = getmntent(mounts)) != NULL) {
		int mntfd;

		if (strcmp(ent->mnt_type, "nsfs") != 0)
			continue;
		bpftune_log(LOG_DEBUG, "checking nsfs mnt %s\n",
			    ent->mnt_dir);
		mntfd = open(ent->mnt_dir, O_RDONLY);
		if (mntfd < 0)
			continue;
		if (bpftune_netns_info(0, &mntfd, &netns_cookie)) {
			close(mntfd);
			continue;
		}
		bpftune_log(LOG_DEBUG, "found netns fd %d for cookie %ld via mnt %s\n",
			    mntfd, netns_cookie, ent->mnt_dir);
		if (cookie == 0) {
			close(mntfd);
			bpftune_for_each_tuner(t)
				bpftuner_netns_init(t, netns_cookie);
			ret = 0;
			continue;
		}
		ret = mntfd;
		endmntent(mounts);
		goto out;
	}
	endmntent(mounts);

	/* move on to /proc-derived namespace fds... */
	dir = opendir("/proc");
	if (!dir) { 
		ret = -errno;   
		bpftune_log(LOG_ERR, "could not open /proc: %s\n", strerror(-ret));
		goto out;
	}
	while ((dirent = readdir(dir)) != NULL) {
		char *endptr;
		int netns_fd;
		long pid;

		pid = strtol(dirent->d_name, &endptr, 10);
		if (!endptr || *endptr != '\0')
			continue;
		if (bpftune_netns_info(pid, &netns_fd, &netns_cookie))
			continue;

		if (cookie == 0) {
			close(netns_fd);
			bpftune_for_each_tuner(t)
				bpftuner_netns_init(t, netns_cookie);
			continue;
		}
		if (netns_cookie == cookie) {
			bpftune_log(LOG_DEBUG, "found netns fd %d for cookie %ld via pid %d\n",
				    netns_fd, netns_cookie, pid);
			ret = netns_fd;
			break;
		} else {
			close(netns_fd);
		}
	}
	closedir(dir);

out:
	bpftune_cap_drop();
	return ret;
}

int bpftuner_netns_fd_from_cookie(struct bpftuner *tuner, unsigned long cookie)
{
	struct bpftuner_netns *netns = bpftuner_netns_from_cookie(tuner->id,
								  cookie);

	if (netns && netns->state >= BPFTUNE_MANUAL) {
		bpftune_log(LOG_DEBUG, "netns (cookie %ld} manually disabled\n",
			    cookie);
		return -ENOENT;
	}
	return bpftune_netns_find(cookie);
}

int bpftune_netns_init_all(void)
{
	unsigned long cookie = 0;

	netns_cookie_supported = bpftune_netns_cookie_supported();
	if (!netns_cookie_supported)
		return 0;

	if (!bpftune_netns_info(getpid(), NULL, &cookie)) {
		global_netns_cookie = cookie;
		bpftune_log(LOG_DEBUG, "global netns cookie is %ld\n",
			    global_netns_cookie);
	}
	return bpftune_netns_find(0);
}

void bpftuner_netns_init(struct bpftuner *tuner, unsigned long cookie)
{
	struct bpftuner_netns *netns, *new = NULL;

	if (bpftuner_netns_from_cookie(tuner->id, cookie))
		return;

	for (netns = &tuner->netns; netns->next != NULL; netns = netns->next) {}

	new = calloc(1, sizeof(struct bpftuner_netns));
	if (!new) {
		bpftune_log(LOG_ERR, "unable to allocate netns for bpftuner: %s\n",
			    strerror(errno));
	} else {
		bpftune_log(LOG_DEBUG, "Added netns (cookie %ld) for tuner '%s'\n",
				       cookie, tuner->name);

		new->netns_cookie = cookie;
		netns->next = new;
	}
}

void bpftuner_netns_fini(struct bpftuner *tuner, unsigned long cookie, enum bpftune_state state)
{
	struct bpftuner_netns *netns, *prev = NULL;

	if (cookie == 0 || cookie == global_netns_cookie) {
		bpftuner_fini(tuner, state);
		return;
	}
	if (!netns_cookie_supported) {
		bpftune_log(LOG_DEBUG, "no netns support and not global netns; ignoring...\n");
		return;
	}

	for (netns = &tuner->netns; netns != NULL; netns = netns->next) {
		if (netns->netns_cookie == cookie) {
			if (state == BPFTUNE_MANUAL) {
				bpftune_log(LOG_DEBUG, "setting state of netns (cookie %ld) to manual for '%s'\n",
					    cookie, tuner->name);
				netns->state = BPFTUNE_MANUAL;
				return;
			}
			if (prev)
				prev->next = netns->next;
			else
				tuner->netns.next = netns->next;
			free(netns);
			return;
		}
		prev = netns;
	}
	bpftune_log(LOG_DEBUG, "netns_fini: could not find netns for cookie %ld\n",
		    cookie);
}

struct bpftuner_netns *bpftuner_netns_from_cookie(unsigned long tuner_id,
						  unsigned long cookie)
{
	struct bpftuner *tuner;
	struct bpftuner_netns *netns;
	
	if (!netns_cookie_supported)
		return NULL;

	bpftune_for_each_tuner(tuner) {
		if (tuner->id != tuner_id)
			continue;
		if (cookie == 0)
			return &tuner->netns;
		bpftuner_for_each_netns(tuner, netns) {
			if (cookie == netns->netns_cookie)
				return netns;
		}
	}
	bpftune_log(LOG_DEBUG, "no tuner netns found for tuner %d, cookie %ld\n",
		    tuner_id, cookie);
	return NULL;
}

static int bpftune_module_path(const char *name, char *modpath, size_t pathsz)
{
	struct utsname utsname;
	int ret;

	if (uname(&utsname) < 0) {
		ret = -errno;
		bpftune_log(LOG_DEBUG, "uname failed: %s\n", strerror(ret));
		return ret;
	}
	snprintf(modpath, pathsz, "/lib/modules/%s/kernel/%s",
		 utsname.release, name);
	return 0;
}

/* load module name, e.g. net/ipv4/foo.ko */
int bpftune_module_load(const char *name)
{
	char modpath[PATH_MAX];
	int ret, fd;

	ret = bpftune_cap_add();
	if (ret)
		return ret;
	ret = bpftune_module_path(name, modpath, sizeof(modpath));
	if (ret)
		goto out;

	fd = open(modpath, O_RDONLY);
	if (fd < 0) {
		bpftune_log(LOG_DEBUG, "no module '%s' found.\n", modpath);
		ret = -errno;
		goto out;
	}
	ret = syscall(__NR_finit_module, fd, "", 0);
	if (ret) {
		bpftune_log(LOG_DEBUG, "could not init module '%s'\n",
			    modpath);
		ret = -errno;
	}
	close(fd);
out:
	bpftune_cap_drop();
	return ret;
}

int bpftune_module_unload(const char *name)
{
	int ret;

	ret = bpftune_cap_add();
	if (ret)
		return ret;
	ret = syscall(__NR_delete_module, name, 0);
	if (ret) {
		bpftune_log(LOG_DEBUG, "could not delete module '%s'\n",
			    name);
		ret = -errno;
	}
	bpftune_cap_drop();
	return ret;
}

static void bpftuner_strategy_update(struct bpftuner *tuner)
{
	struct bpftuner_strategy *strategy, *max_strategy = NULL;
	long double curr, max = 0;

	if (!tuner->strategies)
		return;

	bpftune_log(LOG_DEBUG, "%s: updating strategy...\n", tuner->name);

	bpftuner_for_each_strategy(tuner, strategy) {
		curr = strategy->evaluate(tuner, strategy);
		if (curr < max)
			continue;
		max = curr;
		max_strategy = strategy;
	}
	if (max_strategy && max_strategy != tuner->strategy)
		bpftuner_strategy_set(tuner, max_strategy);
}

static void bpftuner_strategy_timeout(sigval_t sigval)
{
	struct bpftuner *tuner = sigval.sival_ptr;

	if (tuner)
		bpftuner_strategy_update(tuner);
}

int bpftuner_strategy_set(struct bpftuner *tuner,
			  struct bpftuner_strategy *strategy)
{
	bpftune_log(LOG_DEBUG, "setting stragegy for tuner '%s' to '%s': %s\n",
		    tuner->name, strategy->name, strategy->description);
	int err = 0;

	if (!strategy)
		return 0;

	if (tuner->strategy) {
		/* clean up for current strategy */
		bpftune_log(LOG_DEBUG, "%s: cleaning up current strategy '%s'\n",
			    tuner->name, strategy->name);
		tuner->fini(tuner);
	}
	/* arm timer for timeout */
	if (strategy->timeout) {
		struct sigevent sev = {};
		struct itimerspec its = {};
		timer_t tid;

		sev.sigev_notify = SIGEV_THREAD;
		sev.sigev_notify_function = &bpftuner_strategy_timeout;
		sev.sigev_value.sival_ptr = tuner;

		if (timer_create(CLOCK_REALTIME, &sev, &tid)
		    == -1) {
			err = -errno;
			bpftune_log(LOG_DEBUG, "%s: could not arm timer for strategy '%s'\n",
				    strerror(-err));
			return 0;
		}
		its.it_value.tv_sec = strategy->timeout;
		if (timer_settime(tid, 0, &its, NULL)) {
			err = -errno;
			bpftune_log(LOG_DEBUG, "%s: could not arm timer for strategy '%s: %s'\n",
				    tuner->name, strategy->name, strerror(-err));
			return 0;
		}
	}
	if (!err) {
		tuner->strategy = strategy;
		err = tuner->init(tuner);
	}
	return err;
}

int bpftuner_strategies_add(struct bpftuner *tuner, struct bpftuner_strategy **strategies,
			    struct bpftuner_strategy *default_strategy)
{
	struct bpftuner_strategy *strategy;
	unsigned int strategy_id = 0;

	if (!strategies || tuner->strategies)
		return 0;
	tuner->strategies = strategies;
	/* assign ids to each strategy added; used in BPF context */
	bpftuner_for_each_strategy(tuner, strategy)
		strategy->id = strategy_id++;
	if (default_strategy)
		return bpftuner_strategy_set(tuner, default_strategy);
	bpftuner_strategy_update(tuner);
	return 0;
}

bool bpftuner_bpf_prog_in_strategy(struct bpftuner *tuner, const char *prog)
{
	const char **progs;
	int i;

	if (!tuner->strategy || !tuner->strategy->bpf_progs)
		return true;
	progs = tuner->strategy->bpf_progs;

	for (i = 0; progs[i] != NULL; i++) {
		if (strcmp(prog, progs[i]) == 0)
			return true;
	}
	return false;
}

void bpftuner_bpf_set_autoload(struct bpftuner *tuner)
{
	const char **progs;
	int err, i;

	if (!tuner->strategy || !tuner->strategy->bpf_progs)
		return;

	progs = tuner->strategy->bpf_progs;
	for (i = 0; progs[i]; i++) {
		struct bpf_program *prog = bpf_object__find_program_by_name(tuner->obj, progs[i]);
		const char *name;
	
		if (!prog)
			continue;
		name = bpf_program__name(prog);
		if (bpftuner_bpf_prog_in_strategy(tuner, name))
			continue;
		err = bpf_program__set_autoload(prog, false);
		if (err) {
			bpftune_log(LOG_ERR, "%s: could not disable autoload for prog '%s' for strategy '%s': %s\n",
				    tuner->name, name,
				    tuner->strategy->name, strerror(err));
		}
	}
}

void bpftuner_rollback_set(struct bpftuner *tuner)
{
	tuner->rollback = true;
}
