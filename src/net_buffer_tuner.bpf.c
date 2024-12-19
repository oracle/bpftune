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

#ifndef NET_RX_DROP
#define NET_RX_DROP	1
#endif

__u64 drop_count = 0;
__u64 drop_interval_start = 0;

__u64 flow_limit_cpu_bitmap = 0;

int netdev_max_backlog = 0;
int netdev_budget = 0;
int netdev_budget_usecs = 0;

#ifdef BPFTUNE_LEGACY
SEC("kretprobe/enqueue_to_backlog")
int BPF_KRETPROBE(bpftune_enqueue_to_backlog, int ret)
#else
SEC("fexit/enqueue_to_backlog")
int BPF_PROG(bpftune_enqueue_to_backlog, struct sk_buff *skb, int cpu,
	     unsigned int *qtail, int ret)
#endif
{
	int max_backlog = netdev_max_backlog;
	struct bpftune_event event =  { 0 };
	long old[3], new[3];
	__u64 time, cpubit;

	/* a high-frequency event so bail early if we can... */
	if (ret != NET_RX_DROP)
		return 0;

	drop_count++;

	/* only sample subset of drops to reduce overhead. */
	if (bpftune_skip_sample(drop_count))
		return 0;
	
	/* if we drop more than 1/16 of the backlog queue size/min,
	 * increase backlog queue size.  This means as the queue size
	 * increases, the likliehood of hitting that limit decreases.
	 */
	time = bpf_ktime_get_ns();
	if (!drop_interval_start || (time - drop_interval_start) > MINUTE) {
		drop_count = 1;
		drop_interval_start = time;
	}
	if (drop_count >= (max_backlog >> 4)) {
		old[0] = max_backlog;
		new[0] = BPFTUNE_GROW_BY_DELTA(max_backlog);
		send_net_sysctl_event(NULL, NETDEV_MAX_BACKLOG_INCREASE,
				      NETDEV_MAX_BACKLOG, old, new, &event);

#ifdef BPFTUNE_LEGACY
		int cpu = bpf_get_smp_processor_id();
#endif
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

#ifndef BPFTUNE_LEGACY

BPF_MAP_DEF(time_squeeze_map, BPF_MAP_TYPE_PERCPU_ARRAY, unsigned int, unsigned int, 1, 0);

extern const struct softnet_data softnet_data __ksym;

__u64 rx_count = 0;

SEC("fexit/net_rx_action")
int BPF_PROG(net_rx_action)
{
	struct bpftune_event event =  { 0 };
        long old[3], new[3];
	struct softnet_data *sd;
	unsigned int time_squeeze, *last_time_squeezep, last_time_squeeze;
	unsigned int zero = 0;

	if (bpftune_skip_sample(rx_count))
		return 0;
	sd = (struct softnet_data *)bpf_this_cpu_ptr(&softnet_data);
	if (!sd)
		return 0;
	time_squeeze = BPFTUNE_CORE_READ(sd, time_squeeze);
	if (!time_squeeze)
		return 0;
	last_time_squeezep = bpf_map_lookup_elem(&time_squeeze_map, &zero);
	if (!last_time_squeezep)
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
