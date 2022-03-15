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
#define BPFTUNER_LIB_DIR		"/usr/lib64"
#define BPFTUNER_LIB_SUFFIX		"_tuner.so"

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

struct bpftuner *bpftuner_init(const char *path, int perf_map_fd);
int __bpftuner_bpf_init(struct bpftuner *tuner, int perf_map_fd);
int bpftuner_tunables_init(struct bpftuner *tuner, unsigned int num_descs,
			   struct bpftunable_desc *descs);

struct bpftuner *bpftune_tuner(unsigned int index);
unsigned int bpftune_tuner_num(void);
#define bpftune_for_each_tuner(tuner)					     \
	for (unsigned int __i = 0; (tuner = bpftune_tuner(__i)) != NULL; __i++)

void bpftuner_fini(struct bpftuner *tuner);
void bpftuner_bpf_fini(struct bpftuner *tuner);
void bpftuner_tunables_fini(struct bpftuner *tuner);

/* need a macro in order to generate code for skeleton-specific struct */
#define bpftuner_bpf_init(tuner_name, tuner, perf_map_fd)		     \
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
		tuner->tuner_bpf = __skel;				     \
		tuner->skel = __skel->skeleton;				     \
		tuner->perf_map = __skel->maps.perf_map;		     \
		__err = __bpftuner_bpf_init(tuner, perf_map_fd);	     \
		if (__err) {						     \
			tuner_name##_tuner_bpf__destroy(skel);		     \
			return __err;					     \
		}							     \
		__skel->bss->tuner_id = bpftune_tuner_num();		     \
	} while (0)

void *bpftune_perf_buffer_init(int perf_map_fd, int page_cnt, void *ctx);
int bpftune_perf_buffer_poll(void *perf_buffer, int interval);
void bpftune_perf_buffer_fini(void *perf_buffer);

int bpftune_sysctl_read(const char *name, long *values);
int bpftune_sysctl_write(const char *name, __u8 num_values, long *values);

#endif /* __LIBBPFTUNE_H */
