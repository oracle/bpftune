#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
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

struct bpftuner *tuners[BPFTUNE_MAX_TUNERS];
unsigned int num_tuners;

void *perf_buffer;
int perf_map_fd;

static void cleanup(int sig)
{
	bpftune_log(LOG_DEBUG, "cleaning up, got signal %d\n", sig);
	bpftune_perf_buffer_fini(perf_buffer);
}

void fini(void)
{
	unsigned int i;

	for (i = 0; i < num_tuners; i++) {
		bpftuner_fini(tuners[i]);
		tuners[i] = NULL;
	}
}

int init(const char *library_dir, int page_cnt)
{
	char library_path[512];
	struct dirent *dirent;
	DIR *dir;
	int err;

	dir = opendir(library_dir);
	if (!dir) {
		err = -errno;
		bpftune_log(LOG_ERR, "could not open dir '%s': %s\n",
			    library_dir, strerror(-err));
		return err;
	}
	bpftune_log(LOG_DEBUG, "searching %s for plugins...\n", library_dir);
	while ((dirent = readdir(dir)) != NULL) {
		if (strstr(dirent->d_name, BPFTUNER_LIB_SUFFIX) == NULL)
			continue;
		snprintf(library_path, sizeof(library_path), "%s/%s",
			 library_dir, dirent->d_name);
		bpftune_log(LOG_DEBUG, "found lib %s, init\n", library_path);
		tuners[num_tuners] = bpftuner_init(library_path, perf_map_fd);
		/* individual tuner failure shouldn't prevent progress */
		if (!tuners[num_tuners])
			continue;
		tuners[num_tuners]->id = num_tuners;
		if (perf_map_fd == 0)
			perf_map_fd = tuners[num_tuners]->perf_map_fd;
		num_tuners++;
	}

	if (perf_map_fd > 0) {
		perf_buffer = bpftune_perf_buffer_init(perf_map_fd, page_cnt,
						       tuners);
		if (!perf_buffer)
			return -1;
	} else {
		bpftune_log(LOG_ERR, "no perf events to watch, exiting.\n");
		return -ENOENT;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *library_dir = BPFTUNER_LIB_DIR;
	int page_cnt = 8, interval = 100;
	int err;

	bpftune_set_log(LOG_DEBUG, bpftune_log_stderr);

	if (init(library_dir, page_cnt))
		exit(EXIT_FAILURE);

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	err = bpftune_perf_buffer_poll(perf_buffer, interval);

	fini();

	return err;
}
