/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "net_buffer_tuner.h"
#include "net_buffer_tuner.skel.h"
#include "net_buffer_tuner.skel.legacy.h"
#include "net_buffer_tuner.skel.nobtf.h"

#include <limits.h>
#include <unistd.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ NETDEV_MAX_BACKLOG,	BPFTUNABLE_SYSCTL, "net.core.netdev_max_backlog",
								0, 1 },
{ FLOW_LIMIT_CPU_BITMAP,
			BPFTUNABLE_SYSCTL, "net.core.flow_limit_cpu_bitmap",
								0, 1 },
{ NETDEV_BUDGET,	BPFTUNABLE_SYSCTL, "net.core.netdev_budget",
								0, 1 },
{ NETDEV_BUDGET_USECS,	BPFTUNABLE_SYSCTL, "net.core.netdev_budget_usecs",
								0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ NETDEV_MAX_BACKLOG_INCREASE,	"need to increase max backlog size",
	"Need to increase backlog size to prevent drops for faster connection" },
{ FLOW_LIMIT_CPU_SET,		"need to set per-cpu bitmap value",
	"Need to set flow limit per-cpu to prioritize small flows" },
{ NETDEV_BUDGET_INCREASE,	"need to increase # of packets processed per NAPI poll",
	"Need to increase number of packets processed across network devices during NAPI poll to use all of net.core.netdev_budget_usecs" }
};

int init(struct bpftuner *tuner)
{
	long cpu_bitmap = 0;
	long max_backlog = 0;
	long budget = 0;
	long budget_usecs = 0;
	int err;

	bpftune_sysctl_read(0, "net.core.flow_limit_cpu_bitmap", &cpu_bitmap);
	bpftune_sysctl_read(0, "net.core.netdev_max_backlog", &max_backlog);
	bpftune_sysctl_read(0, "net.core.netdev_budget", &budget);
	bpftune_sysctl_read(0, "net.core.netdev_budget_usecs", &budget_usecs);
	err = bpftuner_bpf_open(net_buffer, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(net_buffer, tuner, NULL);
	if (err)
		return err;
	bpftuner_bpf_var_set(net_buffer, tuner, flow_limit_cpu_bitmap,
			     cpu_bitmap);
	bpftuner_bpf_var_set(net_buffer, tuner, netdev_max_backlog,
			     max_backlog);
	bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget,
			     budget);
	bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget_usecs,
			     budget_usecs);
	err = bpftuner_bpf_attach(net_buffer, tuner);
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
	int id, ret;

	/* netns cookie not supported; ignore */
	if (event->netns_cookie == (unsigned long)-1)
		return;

	id = event->update[0].id;
	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for net_buffer_tuner\n", id);
		return;
	}
	switch (id) {
	case NETDEV_MAX_BACKLOG:
		ret = bpftuner_tunable_sysctl_write(tuner, id, scenario,
						    event->netns_cookie, 1,
					            (long int *)event->update[0].new,
"Due to excessive drops, change %s from (%ld) -> (%ld)\n",
					            tunable,
					            event->update[0].old[0],
					            event->update[0].new[0]);
		if (!ret) {
			/* update value of netdev_max_backlog for BPF program */
			bpftuner_bpf_var_set(net_buffer, tuner, netdev_max_backlog,
					     event->update[0].new[0]);
		}
		break;
	case FLOW_LIMIT_CPU_BITMAP:
		bpftuner_tunable_sysctl_write(tuner, id, scenario, 
					      event->netns_cookie, 1,
					      (long int *)event->update[0].new,
"To prioritize small flows, change %s from (%ld) -> (%ld)\n",
					      tunable,
					      event->update[0].old[0],
					      event->update[0].new[0]);
		break;
	case NETDEV_BUDGET:
		if (event->update[0].new[0] > INT_MAX)
			break;
		ret = bpftuner_tunable_sysctl_write(tuner, id, scenario,
						    event->netns_cookie, 1,
						    (long int *)event->update[0].new,
"To maximize # packets processed per NAPI cycle, change %s from (%ld) -> (%ld)\n",
						    tunable,
						    event->update[0].old[0],
						    event->update[0].new[0]);
		if (!ret) {
			long budget_usecs, budget_usecs_new;

			/* update value of netdev_budget for BPF program */
			bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget,
					     event->update[0].new[0]);
			/* need to also update budget_usecs since both
			 * limit netdev budget and reaching either limit
			 * triggers time_squeeze.
			 */
			budget_usecs = bpftuner_bpf_var_get(net_buffer, tuner,
							    netdev_budget_usecs);
			budget_usecs_new = BPFTUNE_GROW_BY_DELTA(budget_usecs);
			ret = bpftuner_tunable_sysctl_write(tuner,
							    NETDEV_BUDGET_USECS,
							    scenario,
							    event->netns_cookie,
							    1,
							    &budget_usecs_new,
"To maximize # packets processed per NAPI cycle, change netdev_budget_usecs from (%ld) -> (%ld)\n",
							    budget_usecs,
							    budget_usecs_new);
			if (!ret)
				bpftuner_bpf_var_set(net_buffer, tuner,
						     netdev_budget_usecs,
						     budget_usecs_new);
		}
		break;
	}
}
