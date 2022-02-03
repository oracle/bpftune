#include <libbpftune.h>
#include "neigh_table_tuner.skel.h"

struct neigh_table_tuner_bpf *skel;

int init(struct bpftuner *tuner, int perf_map_fd)
{
	struct bpf_map *perf_map;
	int err;

	tuner->name = strdup("neigh_table");

	bpftune_log(LOG_DEBUG, "initializing tuner %s, perf_map_fd %d\n",
		    tuner->name, perf_map_fd);

	skel = neigh_table_tuner_bpf__open();

	if (!skel) {
		err = libbpf_get_error(skel);
		bpftune_log_bpf_err(err, "error loading skeleton: %s\n");
		return err;
	}
	perf_map = skel->maps.perf_map;

	if (perf_map_fd > 0) {
		err = bpf_map__reuse_fd(perf_map, perf_map_fd);
		if (err < 0) {
			bpftune_log_bpf_err(err, "could not reuse fd: %s\n");
			goto out;
		}
	}
	err = neigh_table_tuner_bpf__load(skel);
	if (err) {
		bpftune_log_bpf_err(err, "could not load skeleton: %s\n");	
		goto out;
	}
	err = neigh_table_tuner_bpf__attach(skel);
	if (err) {
		bpftune_log_bpf_err(err, "could not attach skeleton: %s\n");
		goto out;
	}
	if (!perf_map_fd)
		perf_map_fd = bpf_map__fd(perf_map);
	tuner->perf_map_fd = perf_map_fd;

out:
	if (err)
		neigh_table_tuner_bpf__destroy(skel);
	return err;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	neigh_table_tuner_bpf__destroy(skel);	
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx)
{
	bpftune_log(LOG_DEBUG, "got scenario %d for tuner %s\n",
		    event->scenario_id, tuner->name);
}
