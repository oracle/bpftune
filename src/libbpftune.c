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

#include "libbpftune.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int bpftune_loglevel = LOG_INFO;
void *bpftune_log_ctx;

struct perf_buffer *perf_buffer;
int perf_map_fd;

static void bpftune_log_stderr(__attribute__((unused)) void *ctx,
			       __attribute__((unused)) int level,
			       const char *fmt, va_list args)
{
	vfprintf(stderr, fmt, args);
}

static void bpftune_log_syslog(__attribute__((unused)) void *ctx, int level,
			       const char *fmt, va_list args)
{
	char buf[512];
	int buflen;

	buflen = vsnprintf(buf, sizeof(buf), fmt, args);
	if (buflen > 0)
		syslog(level, buf, buflen + 1);
}

void (*bpftune_logfn)(void *ctx, int level, const char *fmt, va_list args) =
	bpftune_log_stderr;

static void __bpftune_log(int level, const char *fmt, va_list args)
{
	if (bpftune_loglevel >= level)
		bpftune_logfn(bpftune_log_ctx, level, fmt, args);
}

void bpftune_log(int level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	__bpftune_log(level, fmt, args);
	va_end(args);
}

static int bpftune_printall(__attribute__((unused)) enum libbpf_print_level l,
			    const char *format, va_list args)
{
	__bpftune_log(LOG_DEBUG, format, args);
        return 0;
}

void bpftune_set_logfn(int level,
		       void (*logfn)(void *ctx, int level, const char *fmt,
				     va_list args))
{
	if (logfn)
		bpftune_logfn = logfn;
	if (level > LOG_DEBUG)
		libbpf_set_print(bpftune_printall);
}

void bpftune_log_bpf_err(int err, const char *fmt)
{
	char errbuf[256];

	(void) libbpf_strerror(err, errbuf, sizeof(errbuf));
	bpftune_log(LOG_ERR, fmt, errbuf);
}

/* add a tuner to the list of tuners, or replace existing inactive tuner.
 * If successful, call init().
 */
struct bpftuner *bpftuner_init(const char *path, int perf_map_fd)
{
	struct bpftuner *tuner = NULL;
	int err;

	tuner = calloc(1, sizeof(*tuner));
	if (!tuner) {
		bpftune_log(LOG_ERR, "could not allocate tuner\n");
		return NULL;
	}
	tuner->handle = dlopen(path, 0);
	if (!tuner->handle) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not dlopen '%s': %s\n",
			    path, strerror(-err));
		free(tuner);
		return NULL;
	}
	/* If we have a perf map fd from any tuner, use its fd to be re-used
 	 * for other perf maps (so we can use the same perf buffer for all
 	 * BPF events.
 	 */
	if (perf_map_fd > 0)
		tuner->perf_map_fd = perf_map_fd;
	tuner->init = dlsym(tuner->handle, "init");
	tuner->fini = dlsym(tuner->handle, "fini");
	tuner->event_handler = dlsym(tuner->handle, "event_handler");
	
	err = tuner->init(tuner);
	if (err) {
		dlclose(tuner->handle);
		bpftune_log(LOG_ERR, "error initializing '%s: %s\n",
			    path, strerror(-err));
		free(tuner);
		return NULL;
	}
	return tuner;
}

void bpftuner_fini(struct bpftuner *tuner)
{
	if (!tuner)
		return;
	if (tuner->fini)
		tuner->fini(tuner);
}

static void bpftune_perf_event_lost(__attribute__((unused)) void *ctx, int cpu,
						  __u64 cnt)
{
	bpftune_log(LOG_ERR, "lost %lld events on CPU%d\n", cnt, cpu);
}

static void bpftune_perf_event_read(void *ctx, int cpu, void *data, __u32 size)
{
	struct bpftune_event *event = data;
	struct bpftuner **tuners = ctx;
	struct bpftuner *tuner;

	if (size < sizeof(*event)) {
		bpftune_log(LOG_ERR, "unexpected size event %d, CPU%d\n", size,
			    cpu);
		return;
	}
	if (event->tuner_id > BPFTUNE_MAX_TUNERS) {
		bpftune_log(LOG_ERR, "invalid tuner id %d, CPU%d\n",
			    event->tuner_id, cpu);
		return;
	}
	tuner = tuners[event->tuner_id];
	if (!tuner) {
		bpftune_log(LOG_ERR, "no tuner for id %d, CPU%d\n",
			    event->tuner_id, cpu);
		return;
	}
	bpftune_log(LOG_DEBUG, "event for tuner %s, CPU%d\n", tuner->name, cpu);
	tuner->event_handler(tuner, event, ctx);
}

void *bpftune_perf_buffer_init(int perf_map_fd, int page_cnt,
			       struct bpftuner **tuners)
{
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb;
	int err;

	pb_opts.sample_cb = bpftune_perf_event_read;
	pb_opts.lost_cb = bpftune_perf_event_lost;
	pb_opts.ctx = tuners;
	pb = perf_buffer__new(perf_map_fd, page_cnt, &pb_opts);
	err = libbpf_get_error(perf_buffer);
	if (err) {
		bpftune_log_bpf_err(err, "couldnt create perf buffer: %s\n");
		return NULL;
	}
	return pb;
}

static int perf_buffer_done;

int bpftune_perf_buffer_poll(void *perf_buffer, int interval)
{
	struct perf_buffer *pb = perf_buffer;
	int err;

	while (!perf_buffer_done) {
		err = perf_buffer__poll(pb, interval);
		if (err < 0) {
			bpftune_log_bpf_err(err, "perf_buffer__poll: %s\n");
			break;
		}
	}
	perf_buffer__free(pb);
	return 0;
}

void bpftune_perf_buffer_fini(__attribute__((unused)) void *perf_buffer)
{
	perf_buffer_done = true;
}
