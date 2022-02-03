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

#define BPFTUNER_LIB_DIR		"/usr/lib64"
#define BPFTUNER_LIB_SUFFIX		"_tuner.so"

void bpftune_log(int level, const char *fmt, ...);

void bpftune_log_stderr(void *ctx, int level, const char *fmt, va_list args);
void bpftune_log_syslog(void *ctx, int level, const char *fmt, va_list args);

void bpftune_set_log(int level,
		     void (*logfn)(void *ctx, int level, const char *fmt,
				   va_list args));
void bpftune_log_bpf_err(int err, const char *fmt);

struct bpftuner *bpftuner_init(const char *path, int perf_map_fd);
void bpftuner_fini(struct bpftuner *tuner);

void *bpftune_perf_buffer_init(int perf_map_fd, int page_cnt,
			       struct bpftuner **tuners);
int bpftune_perf_buffer_poll(void *perf_buffer, int interval);
void bpftune_perf_buffer_fini(void *perf_buffer);

