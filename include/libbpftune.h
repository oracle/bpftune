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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/types.h>

#include "bpftune.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define BPFTUNER_CGROUP_DIR		"/tmp/cgroupv2"
#define BPFTUNER_LIB_DIR		"/usr/lib64/bpftune/"
#define BPFTUNER_LIB_SUFFIX		"_tuner.so"

#define BPFTUNE_PROC_SYS		"/proc/sys/"

void bpftune_log(int level, const char *fmt, ...);

void bpftune_log_stderr(void *ctx, int level, const char *fmt, va_list args);
void bpftune_log_syslog(void *ctx, int level, const char *fmt, va_list args);

void bpftune_set_log(int level,
		     void (*logfn)(void *ctx, int level, const char *fmt,
				   va_list args));
void bpftune_log_bpf_err(int err, const char *fmt);


int bpftune_cgroup_init(const char *cgroup_path);
const char *bpftune_cgroup_name(void);
int bpftune_cgroup_fd(void);
void bpftune_cgroup_fini(void);

struct bpftuner *bpftuner_init(const char *path, int ringbuf_map_fd);
int __bpftuner_bpf_init(struct bpftuner *tuner, int ringbuf_map_fd);
int bpftuner_tunables_init(struct bpftuner *tuner, unsigned int num_descs,
			   struct bpftunable_desc *descs);
struct bpftunable *bpftuner_tunable(struct bpftuner *tuner, unsigned int index);
unsigned int bpftuner_tunable_num(struct bpftuner *tuner);
#define bpftuner_for_each_tunable(tuner, tunable)			     \
	for (unsigned int __itun = 0; (tunable = bpftuner_tunable(tuner, __itun)); __itun++)

struct bpftuner *bpftune_tuner(unsigned int index);
unsigned int bpftune_tuner_num(void);
#define bpftune_for_each_tuner(tuner)					     \
	for (unsigned int __it = 0; (tuner = bpftune_tuner(__it)) != NULL; __it++)

void bpftuner_fini(struct bpftuner *tuner, enum bpftune_state state);
void bpftuner_bpf_fini(struct bpftuner *tuner);
void bpftuner_tunables_fini(struct bpftuner *tuner);

/* need a macro in order to generate code for skeleton-specific struct */
#define bpftuner_bpf_init(tuner_name, tuner, ringbuf_map_fd)		     \
	do {								     \
		struct tuner_name##_tuner_bpf *__skel;			     \
		int __err;						     \
									     \
		tuner->name = #tuner_name;				     \
		__skel = tuner_name##_tuner_bpf__open();		     \
		__err = libbpf_get_error(__skel);			     \
		if (__err) {						     \
			bpftune_log_bpf_err(__err,			     \
					    #tuner_name " open bpf: %s\n");  \
			return __err;					     \
		}							     \
		tuner->skel = __skel;				  	     \
		tuner->skeleton = __skel->skeleton;			     \
		tuner->ringbuf_map = __skel->maps.ringbuf_map;		     \
		__err = __bpftuner_bpf_init(tuner, ringbuf_map_fd);	     \
		if (__err) {						     \
			tuner_name##_tuner_bpf__destroy(__skel);	     \
			return __err;					     \
		}							     \
		__skel->bss->tuner_id = bpftune_tuner_num();		     \
	} while (0)

void *bpftune_ring_buffer_init(int ringbuf_map_fd, void *ctx);
int bpftune_ring_buffer_poll(void *ring_buffer, int interval);
void bpftune_ring_buffer_fini(void *ring_buffer);

void bpftune_sysctl_name_to_path(const char *name, char *path, size_t path_sz);
int bpftune_sysctl_read(int netns_fd, const char *name, long *values);
int bpftune_sysctl_write(int netns_fd, const char *name, __u8 num_values, long *values);

int bpftune_netns_set(int fd, int *orig_fd);
int bpftune_netns_info(int pid, int *fd, unsigned long *cookie);
int bpftune_netns_init_all(void);
void bpftuner_netns_init(struct bpftuner *tuner, unsigned long cookie);
void bpftuner_netns_fini(struct bpftuner *tuner, unsigned long cookie);
struct bpftuner_netns *bpftuner_netns_from_cookie(unsigned long tuner_id, unsigned long cookie);
int bpftune_netns_fd_from_cookie(unsigned long cookie);

#define bpftuner_for_each_netns(tuner, netns)				\
	for (netns = &tuner->netns; netns != NULL; netns = netns->next)

#endif /* __LIBBPFTUNE_H */
