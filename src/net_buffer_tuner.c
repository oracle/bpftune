/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "net_buffer_tuner.h"
#include "net_buffer_tuner.skel.h"
#include "net_buffer_tuner.skel.legacy.h"

#include <unistd.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ NETDEV_MAX_BACKLOG,	BPFTUNABLE_SYSCTL, "net.core.netdev_max_backlog",
								false, 1 },
{ FLOW_LIMIT_CPU_BITMAP,
			BPFTUNABLE_SYSCTL, "net.core.flow_limit_cpu_bitmap",
								false, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ NETDEV_MAX_BACKLOG_INCREASE,	"need to increase max backlog size",
	"Need to increase backlog size to prevent drops for faster connection" },
{ FLOW_LIMIT_CPU_SET,		"need to set per-cpu bitmap value",
	"Need to set flow limit per-cpu to prioritize small flows" }
};

int init(struct bpftuner *tuner)
{
	long cpu_bitmap = 0;
	int err;

	bpftune_sysctl_read(0, "net.core.flow_limit_cpu_bitmap", &cpu_bitmap);

	err = bpftuner_bpf_open(net_buffer, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(net_buffer, tuner);
	if (err)
		return err;
	bpftuner_bpf_var_set(net_buffer, tuner, flow_limit_cpu_bitmap,
			     cpu_bitmap);
	err = bpftuner_bpf_attach(net_buffer, tuner, NULL);
	if (err)
		return err;

	return bpftuner_tunables_init(tuner, NET_BUFFER_NUM_TUNABLES, descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	int scenario = event->scenario_id;
	const char *tunable;
	int id;

	/* netns cookie not supported; ignore */
	if (event->netns_cookie == (unsigned long)-1)
		return;

	id = event->update[0].id;
	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for tcp_buffer_tuner\n", id);
		return;
	}
	switch (id) {
	case NETDEV_MAX_BACKLOG:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      event->netns_cookie, 1,
					      (long int *)event->update[0].new,
"Due to excessive drops, change %s from (%d) -> (%d)\n",
					     tunable,
					     event->update[0].old[0],
					     event->update[0].new[0]);
		break;
	case FLOW_LIMIT_CPU_BITMAP:
		bpftuner_tunable_sysctl_write(tuner, id, scenario, 
					      event->netns_cookie, 1,
					      (long int *)event->update[0].new,
"To prioritize small flows, change %s from (%d) -> (%d)\n",
					      tunable,
					      event->update[0].old[0],
					      event->update[0].new[0]);

	}
}
