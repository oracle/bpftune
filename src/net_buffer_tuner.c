/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include <bpftune/corr.h>
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
	"Need to increase number of packets processed across network devices during NAPI poll to use all of net.core.netdev_budget_usecs" },
{ NETDEV_BUDGET_DECREASE,	"need to decrease # of packets processed per NAPI poll",
	"Need to decrease netdev_budget[_usecs] since the ratio of time spent waiting to run versus time spent running for tasks has increased as we have increased netdev budget.  This indicates either our budget increases directly let to increased wait times for other tasks, or that general load has increased; either way spending too much time in NAPI processing will hurt system performance." }
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
	bpftuner_bpf_sample_add(net_buffer, tuner, drop_sample);
	bpftuner_bpf_sample_add(net_buffer, tuner, rx_action_sample);
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
	long new, budget_usecs, budget_usecs_new;
	int scenario = event->scenario_id;
	struct corr c = { 0 };
	long double corr = 0;
	const char *tunable;
	struct corr_key key;
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
		new = event->update[0].new[0];
		if (new > INT_MAX)
			break;
		budget_usecs = bpftuner_bpf_var_get(net_buffer, tuner,
						    netdev_budget_usecs);
		budget_usecs_new = BPFTUNE_GROW_BY_DELTA(budget_usecs);

		ret = bpftune_sched_wait_run_percent_read();
		bpftune_log(LOG_DEBUG, "sched wait-run percent : %d\n", ret);
		if (ret > 0) {
			key.id = (__u64)id;
			key.netns_cookie = event->netns_cookie;
			if (corr_update_user(tuner->corr_map_fd, key.id,
					     key.netns_cookie,
					     (__u64)new, (__u64)ret))
				bpftune_log(LOG_DEBUG, "corr map fd %d update failed %d\n",
					    tuner->corr_map_fd, errno);
		}
		if (!bpf_map_lookup_elem(tuner->corr_map_fd, &key, &c)) {
			corr = corr_compute(&c);
			bpftune_log(LOG_DEBUG, "covar for '%s' netns %ld (new %ld): %LF; corr %LF\n",
				    tunable, key.netns_cookie, new,
				    covar_compute(&c), corr);
			if (corr > CORR_THRESHOLD) {
				new = BPFTUNE_SHRINK_BY_DELTA(event->update[0].old[0]);
				budget_usecs_new = BPFTUNE_SHRINK_BY_DELTA(budget_usecs);
				scenario = NETDEV_BUDGET_DECREASE;
			}
		}
		ret = bpftuner_tunable_sysctl_write(tuner, id, scenario,
						    event->netns_cookie, 1,
						    (long int *)&new,
"To maximize # packets processed per NAPI cycle, change %s from (%ld) -> (%ld)\n",
						    tunable,
						    event->update[0].old[0],
						    new);
		if (!ret) {
			/* update value of netdev_budget for BPF program */
			bpftuner_bpf_var_set(net_buffer, tuner, netdev_budget,
					     new);
			/* need to also update budget_usecs since both
			 * limit netdev budget and reaching either limit
			 * triggers time_squeeze.
			 */
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
