#include <libbpftune.h>
#include "neigh_table_tuner.skel.h"

struct neigh_table_tuner_bpf *skel;

struct bpftunable_desc descs[] = {
{ 0,	BPFTUNABLE_SYSCTL,	"net.ipv4.neigh.default.gc_interval",	1 },
{ 1,	BPFTUNABLE_SYSCTL,	"net.ipv4.neigh.default.gc_stale_time",	1, },
{ 2,	BPFTUNABLE_SYSCTL,	"net.ipv4.neigh.default.gc_thresh1",	1, },
{ 3,	BPFTUNABLE_SYSCTL,	"net.ipv4.neigh.default.gc_thresh2",	1, },
{ 4,	BPFTUNABLE_SYSCTL,	"net.ipv4.neigh.default.gc_thresh3",	1, },
};

int init(struct bpftuner *tuner, int perf_map_fd)
{
	struct bpftunable *tunables;

	bpftuner_bpf_init(neigh_table, tuner, perf_map_fd);
	return bpftuner_tunables_init(tuner, 5, descs);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx)
{
	bpftune_log(LOG_DEBUG, "got scenario %d for tuner %s\n",
		    event->scenario_id, tuner->name);
}
