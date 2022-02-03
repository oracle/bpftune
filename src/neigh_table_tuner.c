#include <libbpftune.h>
#include "neigh_table_tuner.skel.h"

struct neigh_table_tuner_bpf *skel;

int init(struct bpftuner *tuner, int perf_map_fd)
{
	bpftuner_bpf_init(neigh_table, tuner, perf_map_fd);
	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpf_object__destroy_skeleton(tuner->skel);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx)
{
	bpftune_log(LOG_DEBUG, "got scenario %d for tuner %s\n",
		    event->scenario_id, tuner->name);
}
