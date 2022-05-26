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
#include <fcntl.h>
#include <dirent.h>
#include <libgen.h>
#include <linux/limits.h>
#include <linux/types.h>
#include <sys/mount.h>

#include "libbpftune.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int bpftune_loglevel = LOG_INFO;
void *bpftune_log_ctx;

struct ring_buffer *ring_buffer;
int ring_buffer_fd;

void bpftune_log_stderr(__attribute__((unused)) void *ctx,
			__attribute__((unused)) int level,
			const char *fmt, va_list args)
{
	vfprintf(stderr, fmt, args);
}

void bpftune_log_syslog(__attribute__((unused)) void *ctx, int level,
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
	if (level <= bpftune_loglevel)
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

void bpftune_set_log(int level,
		     void (*logfn)(void *ctx, int level, const char *fmt,
				   va_list args))
{
	if (logfn)
		bpftune_logfn = logfn;
	bpftune_loglevel = level;
	if (level >= LOG_DEBUG)
		libbpf_set_print(bpftune_printall);
}

void bpftune_log_bpf_err(int err, const char *fmt)
{
	char errbuf[256];

	(void) libbpf_strerror(err, errbuf, sizeof(errbuf));
	bpftune_log(LOG_ERR, fmt, errbuf);
}

static char bpftune_cgroup_path[PATH_MAX];
static int __bpftune_cgroup_fd;

int bpftune_cgroup_init(const char *cgroup_path)
{
	int err;

	strncpy(bpftune_cgroup_path, cgroup_path, sizeof(bpftune_cgroup_path));
	__bpftune_cgroup_fd = open(cgroup_path, O_RDONLY);
	if (__bpftune_cgroup_fd < 0) {
		if (!mkdir(cgroup_path, 0777)) {
			err = -errno;
			bpftune_log(LOG_ERR, "couldnt create cgroup dir '%s': %s\n",
				    cgroup_path, strerror(-err));
                        return err;
                }
		if (!mount("none" , cgroup_path, "cgroup2", 0, NULL)) {
			err = -errno;
			bpftune_log(LOG_ERR, "couldnt mount cgroup2 for '%s': %s\n",
				    strerror(-err));
			return err;
		}
		__bpftune_cgroup_fd = open(cgroup_path, O_RDONLY);
		if (__bpftune_cgroup_fd < 0) {
			err = -errno;
			bpftune_log(LOG_ERR, "cannot open cgroup dir '%s': %s\n",
				    cgroup_path, strerror(-err));
			return err;
		}
	}
	return 0;
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

int __bpftuner_bpf_init(struct bpftuner *tuner, int ring_buffer_fd)
{
	int err;	

	if (ring_buffer_fd > 0) {
		err = bpf_map__reuse_fd(tuner->ringbuf_map, ring_buffer_fd);
		if (err < 0) {
			bpftune_log_bpf_err(err, "could not reuse fd: %s\n");
			return err;
		}
	}
	err = bpf_object__load_skeleton(tuner->skeleton);
	if (err) {
		bpftune_log_bpf_err(err, "could not load skeleton: %s\n");      
		return err;
	}
	/* may need to attach cgroup later, don't fail */
	err = bpf_object__attach_skeleton(tuner->skeleton);
	if (err) {
		bpftune_log_bpf_err(err, "could not attach skeleton: %s\n");
		return err;
	}
	if (!ring_buffer_fd)
		ring_buffer_fd = bpf_map__fd(tuner->ringbuf_map);
	tuner->ringbuf_map_fd = ring_buffer_fd;

	return 0;
}

void bpftuner_bpf_fini(struct bpftuner *tuner)
{
	bpf_object__destroy_skeleton(tuner->skeleton);
	free(tuner->skel);
}

static struct bpftuner *bpftune_tuners[BPFTUNE_MAX_TUNERS];
static unsigned int bpftune_num_tuners;

/* add a tuner to the list of tuners, or replace existing inactive tuner.
 * If successful, call init().
 */
struct bpftuner *bpftuner_init(const char *path, int ringbuf_map_fd)
{
	struct bpftuner *tuner = NULL;
	int err;

	tuner = calloc(1, sizeof(*tuner));
	if (!tuner) {
		bpftune_log(LOG_ERR, "could not allocate tuner\n");
		return NULL;
	}
	tuner->handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if (!tuner->handle) {
		bpftune_log(LOG_ERR, "could not dlopen '%s': %s\n",
			    path, dlerror());
		free(tuner);
		return NULL;
	}
	/* If we have a perf map fd from any tuner, use its fd to be re-used
 	 * for other perf maps (so we can use the same perf buffer for all
 	 * BPF events.
 	 */
	if (ringbuf_map_fd > 0)
		tuner->ringbuf_map_fd = ringbuf_map_fd;
	tuner->init = dlsym(tuner->handle, "init");
	tuner->fini = dlsym(tuner->handle, "fini");
	tuner->event_handler = dlsym(tuner->handle, "event_handler");
	
	bpftune_log(LOG_DEBUG, "calling init for '%s\n", path);
	err = tuner->init(tuner, ringbuf_map_fd);
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
	bpftune_log(LOG_DEBUG, "sucessfully intialized tuner %s[%d]\n",
		    tuner->name, tuner->id);
	return tuner;
}

void bpftuner_fini(struct bpftuner *tuner, enum bpftune_state state)
{
	if (!tuner || tuner->state != BPFTUNE_ACTIVE)
		return;
	if (tuner->fini)
		tuner->fini(tuner);
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
	bpftune_log(LOG_DEBUG, "event[%d] for tuner %s[%d]\n",
		    event->tuner_id, tuner->name, tuner->id);
	tuner->event_handler(tuner, event, ctx);

	return 0;
}

void *bpftune_ring_buffer_init(int ringbuf_map_fd, void *ctx)
{
	struct ring_buffer *rb;
	int err;

	bpftune_log(LOG_DEBUG, "calling ring_buffer__new, ringbuf_map_fd %d\n",
		    ringbuf_map_fd);
	rb = ring_buffer__new(ringbuf_map_fd, bpftune_ringbuf_event_read, ctx, NULL);
	err = libbpf_get_error(rb);
	if (err) {
		bpftune_log_bpf_err(err, "couldnt create ring buffer: %s\n");
		return NULL;
	}
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
			bpftune_log_bpf_err(err, "ring_buffer__poll: %s\n");
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

int bpftune_sysctl_read(const char *name, long *values)
{
	int i, num_values = 0;
	char path[512];
	int err = 0;	
	FILE *fp;

	bpftune_sysctl_name_to_path(name, path, sizeof(path));

	fp = fopen(path, "r");
	if (!fp) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not open %s for reading: %s\n",
			    path, strerror(-err));
		return err;
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
		return err;
	}

	for (i = 0; i < num_values; i++) {
		bpftune_log(LOG_DEBUG, "Read %s[%d] = %ld\n",
			    name, i, values[i]);
	}

	return num_values;
}

int bpftune_sysctl_write(const char *name, __u8 num_values, long *values)
{
	long old_values[BPFTUNE_MAX_VALUES];
	__u8 old_num_values;
	char path[512];
	int i, err = 0;
	FILE *fp;

	bpftune_sysctl_name_to_path(name, path, sizeof(path));

	/* If value is already set to val, do nothing. */
	old_num_values = bpftune_sysctl_read(path, old_values);
	if (err)
		return err;
	if (num_values == old_num_values) {
		for (i = 0; i < num_values; i++) {
			if (old_values[i] != values[i])
				break;
		}
		if (i == num_values)
			return 0;
	}
        fp = fopen(path, "w");
        if (!fp) {
                err = -errno;
                bpftune_log(LOG_DEBUG, "could not open %s for writing: %s\n",
			    path, strerror(-err));
                return err;
        }

	for (i = 0; i < num_values; i++)
		fprintf(fp, "%ld ", values[i]);
        fclose(fp);

	for (i = 0; i < num_values; i++) {
		bpftune_log(LOG_DEBUG, "Wrote %s[%d] = %ld\n",
			    name, i, values[i]);
	}
        return 0;
}

int bpftuner_tunables_init(struct bpftuner *tuner, unsigned int num_descs,
			   struct bpftunable_desc *descs)
{
	unsigned int i;

	tuner->tunables = calloc(num_descs, sizeof(struct bpftunable));
	if (!tuner->tunables) {
		bpftune_log(LOG_DEBUG, "no memory to alloc tunables for %s\n",
			    tuner->name);
		return -ENOMEM;
	}
	tuner->num_tunables = num_descs;
	for (i = 0; i < num_descs; i++) {
		int num_values;

		memcpy(&tuner->tunables[i].desc, &descs[i], sizeof(*descs));

		if (descs[i].type != BPFTUNABLE_SYSCTL) {
			bpftune_log(LOG_ERR, "cannot add '%s': only sysctl tunables supported\n",
				    descs[i].name);
			return -EINVAL;
		}
		num_values = bpftune_sysctl_read(descs[i].name,
				tuner->tunables[i].current_values);
		if (num_values < 0) {
			bpftune_log(LOG_ERR, "error reading tunable '%s': %s\n",
				    descs[i].name, strerror(-num_values));
			return num_values;
		}
		if (num_values != descs[i].num_values) {
			bpftune_log(LOG_ERR, "error reading tunable '%s'; expected %d values, got %d\n",
				    descs[i].num_values, num_values);
			return -EINVAL;
		}
	}

	return 0;
}

struct bpftunable *bpftuner_tunable(struct bpftuner *tuner, unsigned int index)
{
	if (index < tuner->num_tunables)
		return &tuner->tunables[index];
	return NULL;
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
