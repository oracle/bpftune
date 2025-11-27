/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <bpftune/bpftune.bpf.h>
#include "net_buffer_tuner.h"

#ifndef NET_RX_SUCCESS
#define NET_RX_SUCCESS	0
#endif
#ifndef NET_RX_DROP
#define NET_RX_DROP	1
#endif

__u64 drop_count = 0;
__u64 drop_interval_start = 0;

__u64 flow_limit_cpu_bitmap = 0;

int netdev_max_backlog = 0;
int netdev_budget = 0;
int netdev_budget_usecs = 0;

struct bpftune_sample drop_sample = {};
struct bpftune_sample process_backlog_sample = {};

BPF_MAP_DEF(time_squeeze_map, BPF_MAP_TYPE_PERCPU_ARRAY, unsigned int, unsigned int, 1, 0);

extern const struct softnet_data softnet_data __ksym;

static __always_inline int update_backlog(void)
{
	int max_backlog = netdev_max_backlog;
	struct bpftune_event event =  { 0 };
	long old[3] = { 0, 0, 0 };
	long new[3] = { 0, 0, 0 };
	__u64 time, cpubit;
	int cpu;

	drop_count++;

	/* if we drop more than 1/32 of the backlog queue size/min,
	 * increase backlog queue size.  This means as the queue size
	 * increases, the likliehood of hitting that limit decreases.
	 */
	time = bpf_ktime_get_ns();
	if (!drop_interval_start || (time - drop_interval_start) > MINUTE) {
		drop_count = 1;
		drop_interval_start = time;
	}
	if (drop_count >= (max_backlog >> 5)) {
		old[0] = max_backlog;
		new[0] = BPFTUNE_GROW_BY_DELTA(max_backlog);
		send_net_sysctl_event(NULL, NETDEV_MAX_BACKLOG_INCREASE,
				      NETDEV_MAX_BACKLOG, old, new, &event);

		cpu = bpf_get_smp_processor_id();
		/* ensure flow limits prioritize small flows on this cpu */
		if (cpu < 64) {
			cpubit = 1 << cpu;
			if (!(flow_limit_cpu_bitmap & cpubit)) {
				old[0] = flow_limit_cpu_bitmap;
				new[0] = flow_limit_cpu_bitmap |= cpubit;
				if (!send_net_sysctl_event(NULL, FLOW_LIMIT_CPU_SET,
							   FLOW_LIMIT_CPU_BITMAP,
							  old, new, &event))
					flow_limit_cpu_bitmap = new[0];
			}
		}
	}
	return 0;
}

#ifdef BPFTUNE_LEGACY
SEC("kretprobe/enqueue_to_backlog")
int BPF_KRETPROBE(bpftune_enqueue_to_backlog, int ret)
{
	if (ret != NET_RX_DROP)
		return 0;
	drop_count++;

	/* only sample subset of drops to reduce overhead. */
	bpftune_sample(drop_sample);
	return update_backlog();
}
#else
SEC("tp_btf/kfree_skb")
int BPF_PROG(bpftune_kfree_skb, struct sk_buff *skb, void *location,
	     enum skb_drop_reason reason)
{
	if (bpf_core_enum_value_exists(enum skb_drop_reason, SKB_DROP_REASON_CPU_BACKLOG)) {
		int backlog_reason = bpf_core_enum_value(enum skb_drop_reason,
							 SKB_DROP_REASON_CPU_BACKLOG);
		if (reason == backlog_reason) {
			drop_count++;
			return update_backlog();
		}
	}
	return 0;
}
#endif

#ifndef BPFTUNE_LEGACY
SEC("fexit/process_backlog")
int BPF_PROG(bpftune_process_backlog, struct napi_struct *napi, int quota,
	     int ret)
{
	struct bpftune_event event =  { 0 };
	long old[3] = { 0, 0, 0 };
	long new[3] = { 0, 0, 0 };
	struct softnet_data *sd;
	unsigned int time_squeeze, last_time_squeeze;
	unsigned int *last_time_squeezep = NULL;
	unsigned int zero = 0;

	/* no pending data */
	if (ret == 0)
		return 0;
	/* only sample subset of drops to reduce overhead. */
	bpftune_sample(process_backlog_sample);

	sd = (struct softnet_data *)bpf_this_cpu_ptr(&softnet_data);
	if (!sd)
		return 0;
	time_squeeze = BPFTUNE_CORE_READ(sd, time_squeeze);
	if (!time_squeeze)
		return 0;
	last_time_squeezep = bpf_map_lookup_elem(&time_squeeze_map, &zero);
	if (last_time_squeezep == NULL)
		return 0;
	last_time_squeeze = *last_time_squeezep;
	if (time_squeeze <= last_time_squeeze)
		return 0;
	*last_time_squeezep = time_squeeze;
	/* did not have previous time_squeeze value for comparison, bail. */
	if (!(last_time_squeeze))
		return 0;
	old[0] = (long)netdev_budget;
	new[0] = BPFTUNE_GROW_BY_DELTA((long)netdev_budget);
	send_net_sysctl_event(NULL, NETDEV_BUDGET_INCREASE,
			      NETDEV_BUDGET, old, new, &event);
	return 0;
}
#endif
