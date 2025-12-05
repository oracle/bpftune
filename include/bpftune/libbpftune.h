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

#ifndef __LIBBPFTUNE_H
#define __LIBBPFTUNE_H

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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/types.h>
#include <pthread.h>

#include <bpftune/bpftune.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPFTUNE_RUN_DIR			"/var/run/bpftune"
#define BPFTUNE_PORT_FILE		BPFTUNE_RUN_DIR	"/server-port"
#define BPFTUNER_CGROUP_DIR		BPFTUNE_RUN_DIR "/cgroupv2"
#ifndef BPFTUNER_PREFIX_DIR
#define BPFTUNER_PREFIX_DIR		"/usr"
#endif
#ifndef LIB_DIR
#define LIB_DIR				"lib64"
#endif
/* default /usr/lib64/bpftune */
#define BPFTUNER_LIB_DIR		BPFTUNER_PREFIX_DIR "/" LIB_DIR "/bpftune/"
/* default /usr/local/lib64/bpftune */
#define BPFTUNER_LOCAL_LIB_DIR		BPFTUNER_PREFIX_DIR "/local/" LIB_DIR "/bpftune/"
#define BPFTUNER_LIB_SUFFIX		"_tuner.so"

#define BPFTUNE_PROC_SYS		"/proc/sys/"

#define BPFTUNE_PIN			"/sys/fs/bpf/bpftune"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)			(sizeof(arr) / sizeof((arr)[0])) 
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

#define BPFTUNE_SERVER_MSG_MAX		65536

char *bpftune_state_string[] = {
	"inactive",
	"active",
	"manual",
	"gone",
};

/* level for bpftune tunable updates */
#define BPFTUNE_LOG_LEVEL		LOG_NOTICE

/* write to buffer and log using nextlogfn */
struct bpftune_log_ctx_buf {
	void (*nextlogfn)(void *ctx, int level, const char *fmt, va_list args);
	pthread_t buf_thread;
	char *buf;
	size_t buf_off;
	size_t buf_sz;
};

int bpftune_log_level(void);

void bpftune_log(int level, const char *fmt, ...);

void bpftune_log_stderr(void *ctx, int level, const char *fmt, va_list args);
void bpftune_log_syslog(void *ctx, int level, const char *fmt, va_list args);
void bpftune_log_buf(void *ctx, int level, const char *fmt, va_list args);

void bpftune_set_log(int level,
		     void (*logfn)(void *ctx, int level, const char *fmt,
				   va_list args),
		     void *ctx);
void bpftune_set_bpf_log(bool log);

void bpftune_log_bpf_err(int err, const char *fmt);

int bpftune_cap_add(void);
void bpftune_cap_drop(void);

extern unsigned short bpftune_learning_rate;

void bpftune_set_learning_rate(unsigned short rate);

int bpftune_cgroup_init(const char *cgroup_path);
const char *bpftune_cgroup_name(void);
int bpftune_cgroup_fd(void);
void bpftune_cgroup_fini(void);

int bpftune_server_start(unsigned short port);
int bpftune_server_port(void);
void bpftune_server_stop(void);
int bpftune_server_request(struct sockaddr_in *server, const char *req,
			   char *buf, size_t buf_sz);

int bpftuner_cgroup_attach(struct bpftuner *tuner, const char *prog_name,
			   enum bpf_attach_type attach_type);
void bpftuner_cgroup_detach(struct bpftuner *tuner, const char *prog_name,
			    enum bpf_attach_type attach_type);


struct bpftuner *bpftuner_init(const char *path);
int __bpftuner_bpf_load(struct bpftuner *tuner, const char **optionals, bool quiet);
int __bpftuner_bpf_attach(struct bpftuner *tuner);

int bpftuner_tunables_init(struct bpftuner *tuner, unsigned int num_descs,
			   struct bpftunable_desc *descs,
			   unsigned int num_scenarios,
			   struct bpftunable_scenario *scenarios);
struct bpftunable *bpftuner_tunable(struct bpftuner *tuner, unsigned int index);
unsigned int bpftuner_num_tunables(struct bpftuner *tuner);

static inline const char *bpftuner_tunable_name(struct bpftuner *tuner,
						unsigned int index)
{
	struct bpftunable *t = bpftuner_tunable(tuner, index);
	return t ? t->desc.name : NULL;
}

#define bpftuner_for_each_tunable(tuner, tunable)			     \
	for (unsigned int __itun = 0; (tunable = bpftuner_tunable(tuner, __itun)); __itun++)

#define bpftuner_for_each_strategy(tuner, strategy)			     \
	for (unsigned int __s = 0; (strategy = tuner->strategies[__s]); __s++)

int bpftuner_tunable_sysctl_write(struct bpftuner *tuner,
				  unsigned int tunable,
				  unsigned int scenario,
				  unsigned long netns_cookie,
				  __u8 num_values, void *values,
				  const char *fmt, ...);

int bpftuner_tunable_update(struct bpftuner *tuner,
			    unsigned int tunable,
			    unsigned int scenario,
			    int netns_fd,
			    const char *fmt, ...);

void bpftuner_tunable_stats_update(struct bpftuner *tuner,
				   unsigned int tunable,
				   unsigned int scenario, bool global_ns,
				   unsigned long val);

struct bpftuner *bpftune_tuner(unsigned int index);
unsigned int bpftune_tuner_num(void);
#define bpftune_for_each_tuner(tuner)					     \
	for (unsigned int __it = 0; (tuner = bpftune_tuner(__it)) != NULL; __it++)

void bpftuner_fini(struct bpftuner *tuner, enum bpftune_state state);
void bpftuner_bpf_fini(struct bpftuner *tuner);
void bpftuner_tunables_fini(struct bpftuner *tuner);

/* need a macro in order to generate code for skeleton-specific struct */

#define __bpftuner_bpf_open(tuner_name, tuner, suffix)			     \
	do {								     \
		struct tuner_name##_tuner_##suffix *__skel;		     \
		tuner->skel = __skel = tuner_name##_tuner_##suffix##__open();\
		tuner->skeleton = __skel->skeleton;			     \
		__skel->bss->debug = bpftune_log_level() >= LOG_DEBUG;	     \
		__skel->bss->bpftune_pid = getpid();			     \
		__skel->bss->bpftune_learning_rate = bpftune_learning_rate;  \
		__skel->bss->tuner_id = bpftune_tuner_num();		     \
		__skel->bss->bpftune_init_net =				     \
				bpftune_ksym_addr('B', "init_net");	     \
		if (tuner->strategy)					     \
			__skel->bss->strategy_id = tuner->strategy->id;	     \
		tuner->obj = __skel->obj;				     \
		tuner->ring_buffer_map = __skel->maps.ring_buffer_map;	     \
		tuner->netns_map = __skel->maps.netns_map;		     \
		tuner->corr_map = __skel->maps.corr_map;		     \
	} while (0)

#define bpftuner_bpf_open(tuner_name, tuner) ({				     \
	int __err = bpftune_cap_add();					     \
                                                                             \
	if (!__err) {							     \
		tuner->name = #tuner_name;				     \
		tuner->bpf_support = bpftune_bpf_support();		     \
		switch (tuner->bpf_support) {				     \
		case BPFTUNE_SUPPORT_NORMAL:				     \
			__bpftuner_bpf_open(tuner_name, tuner, bpf);	     \
			break;						     \
		case BPFTUNE_SUPPORT_LEGACY:				     \
			__bpftuner_bpf_open(tuner_name, tuner, bpf_legacy);  \
			break;						     \
		case BPFTUNE_SUPPORT_NOBTF:				     \
			__bpftuner_bpf_open(tuner_name, tuner, bpf_nobtf);   \
			break;						     \
		default:						     \
			break;						     \
		}							     \
		bpftune_cap_drop();					     \
	}								     \
	__err = libbpf_get_error(tuner->skel);				     \
	if (__err) {							     \
		bpftune_log_bpf_err(__err,				     \
				    #tuner_name " open bpf: %s\n");	     \
	}								     \
	__err;								     \
})

#define bpftuner_bpf_destroy(tuner_name, tuner)				     \
	do {								     \
		switch (tuner->bpf_support) {				     \
		case BPFTUNE_SUPPORT_NORMAL:				     \
			tuner_name##_tuner_bpf__destroy(tuner->skel);	     \
			break;						     \
		case BPFTUNE_SUPPORT_LEGACY:				     \
			tuner_name##_tuner_bpf_legacy__destroy(tuner->skel); \
			break;						     \
		case BPFTUNE_SUPPORT_NOBTF:				     \
			tuner_name##_tuner_bpf_nobtf__destroy(tuner->skel);  \
			break;						     \
		default:						     \
			break;						     \
		}							     \
	} while (0)

#define bpftuner_bpf_load(tuner_name, tuner, optionals) ({		     \
	int __err;							     \
									     \
	__err = __bpftuner_bpf_load(tuner, NULL, optionals != NULL);	     \
	if (__err && optionals != NULL) {				     \
		bpftuner_bpf_fini(tuner);				     \
		__err = bpftuner_bpf_open(tuner_name, tuner);		     \
		if (!__err)						     \
			__err = __bpftuner_bpf_load(tuner, optionals, false);\
	}								     \
	if (__err)							     \
		bpftuner_bpf_destroy(tuner_name, tuner);		     \
	__err;								     \
})

#define bpftuner_bpf_attach(tuner_name, tuner) ({		     	     \
	int __err = __bpftuner_bpf_attach(tuner);			     \
	__err;								     \
})

#define bpftuner_bpf_init(tuner_name, tuner, optionals) ({		     \
	int __err = bpftuner_bpf_open(tuner_name, tuner);		     \
									     \
	if (!__err)							     \
		__err = bpftuner_bpf_load(tuner_name, tuner, optionals);		     \
	if (!__err)							     \
		bpftuner_bpf_attach(tuner_name, tuner);			     \
	__err;								     \
})

#define bpftuner_bpf_skel_val(tuner_name, tuner, val)			     \
	(tuner->bpf_support == BPFTUNE_SUPPORT_NORMAL ?		   	     \
	 ((struct tuner_name##_tuner_bpf *)tuner->skel)->val :		     \
	 tuner->bpf_support == BPFTUNE_SUPPORT_LEGACY ?			     \
	 ((struct tuner_name##_tuner_bpf_legacy *)tuner->skel)->val :	     \
	 ((struct tuner_name##_tuner_bpf_nobtf *)tuner->skel)->val)

#define bpftuner_bpf_var_set(tuner_name, tuner, var, val)		     \
	do {								     \
		struct tuner_name##_tuner_bpf *__skel = tuner->skel;	     \
                struct tuner_name##_tuner_bpf_legacy *__lskel = tuner->skel; \
		struct tuner_name##_tuner_bpf_nobtf *__nskel = tuner->skel;  \
		switch (tuner->bpf_support) {				     \
		case BPFTUNE_SUPPORT_NORMAL:				     \
			__skel->bss->var = val;				     \
			break;						     \
		case BPFTUNE_SUPPORT_LEGACY:				     \
			__lskel->bss->var = val;			     \
			break;						     \
		case BPFTUNE_SUPPORT_NOBTF:				     \
			__nskel->bss->var = val;			     \
		default:						     \
			break;						     \
		}							     \
		bpftune_log(LOG_DEBUG, "%s: set variable '%s' = '%ld'\n",    \
			    #tuner_name, #var, (long)val);		     \
	} while (0)

#define bpftuner_bpf_var_get(tuner_name, tuner, var)			     \
	bpftuner_bpf_skel_val(tuner_name, tuner, bss->var)

#define bpftuner_bpf_map_get(tuner_name, tuner, map)			     \
	bpftuner_bpf_skel_val(tuner_name, tuner, maps.map)

#define bpftuner_bpf_sample_add(tuner_name, tuner, s)		     	     \
	do {								     \
		struct tuner_name##_tuner_bpf *__skel = tuner->skel;	     \
		struct tuner_name##_tuner_bpf_legacy *__lskel = tuner->skel; \
		struct tuner_name##_tuner_bpf_nobtf *__nskel = tuner->skel;  \
		struct bpftune_sample_desc *d;				     \
		d = &tuner->samples[tuner->num_samples];		     \
		d->name = #s;						     \
		switch (tuner->bpf_support) {				     \
                case BPFTUNE_SUPPORT_NORMAL:				     \
                        d->sample = &__skel->bss->s;			     \
                        break;                                               \
                case BPFTUNE_SUPPORT_LEGACY:                                 \
                        d->sample = &__lskel->bss->s;			     \
                        break;                                               \
                case BPFTUNE_SUPPORT_NOBTF:                                  \
                        d->sample = &__nskel->bss->s;			     \
                default:						     \
                        break;                                               \
                }                                                            \
		tuner->num_samples++;					     \
                bpftune_log(LOG_DEBUG, "%s: added sample '%s'\n",	     \
                            #tuner_name, #s);				     \
	} while (0)


enum bpftune_support_level bpftune_bpf_support(void);
bool bpftune_have_vmlinux_btf(void);
void bpftune_force_bpf_support(enum bpftune_support_level);

int bpftuner_ring_buffer_map_fd(struct bpftuner *tuner);
void *bpftune_ring_buffer_init(int ringbuf_map_fd, void *ctx);
int bpftune_ring_buffer_poll(void *ring_buffer, int interval);
void bpftune_ring_buffer_fini(void *ring_buffer);

void bpftune_sysctl_name_to_path(const char *name, char *path, size_t path_sz);
int bpftune_sysctl_read(int netns_fd, const char *name, long *values);
int bpftune_sysctl_read_string(int netns_fd, const char *name, char *val);
int bpftune_sysctl_write(int netns_fd, const char *name, __u8 num_values, long *values);
int bpftune_sysctl_write_string(int netns_fd, const char *name, char *val);
long long bpftune_ksym_addr(char type, const char *name);
int bpftune_snmpstat_read(unsigned long netns_cookie, int family, const char *linename, const char *name, long *value);
int bpftune_netstat_read(unsigned long netns_cookie, int family, const char *linename, const char *name, long *value);
int bpftune_sched_wait_run_percent_read(void);
bool bpftune_netns_cookie_supported(void);
unsigned long bpftune_global_netns_cookie(void);
int bpftune_netns_set(int fd, int *orig_fd, bool quiet);
int bpftune_netns_info(int pid, int *fd, unsigned long *cookie);
int bpftune_netns_init_all(void);
void bpftuner_netns_init(struct bpftuner *tuner, unsigned long cookie);
void bpftuner_netns_fini(struct bpftuner *tuner, unsigned long cookie, enum bpftune_state state);
struct bpftuner_netns *bpftuner_netns_from_cookie(unsigned long tuner_id, unsigned long cookie);
int bpftuner_netns_fd_from_cookie(struct bpftuner *tuner, unsigned long cookie);

#define bpftuner_for_each_netns(tuner, netns)				\
	for (netns = &tuner->netns; netns != NULL; netns = netns->next)

int bpftune_module_load(const char *name);
int bpftune_module_unload(const char *name);

int bpftuner_strategy_set(struct bpftuner *tuner, struct bpftuner_strategy *strategy);
int bpftuner_strategies_add(struct bpftuner *tuner, struct bpftuner_strategy **strategies,
			    struct bpftuner_strategy *default_strategy);
bool bpftuner_bpf_prog_in_strategy(struct bpftuner *tuner, const char *prog);
void bpftuner_bpf_set_autoload(struct bpftuner *tuner);

void bpftuner_rollback_set(struct bpftuner *tuner);

#endif /* __LIBBPFTUNE_H */
