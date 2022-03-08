#include <libbpftune.h>
#include "sysctl_tuner.skel.h"

struct sysctl_tuner_bpf *skel;

int init(struct bpftuner *tuner, int perf_map_fd)
{
	bpftuner_bpf_init(sysctl, tuner, perf_map_fd);

	/* attach to root cgroup */
	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   void *ctx)
{
	bpftune_log(LOG_DEBUG, "sysctl write for '%s' (scenario %d) for tuner %s\n",
		    event->str, event->scenario_id, tuner->name);
}
