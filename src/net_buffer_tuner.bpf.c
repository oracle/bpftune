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

extern const void netdev_max_backlog __ksym;

#ifndef NET_RX_DROP
#define NET_RX_DROP	1
#endif

__u64 drop_count = 0;
__u64 drop_interval_start = 0;

__u64 flow_limit_cpu_bitmap = 0;

#ifdef BPFTUNE_LEGACY
SEC("kretprobe/enqueue_to_backlog")
int BPF_KRETPROBE(bpftune_enqueue_to_backlog, int ret)
#else
SEC("fexit/enqueue_to_backlog")
int BPF_PROG(bpftune_enqueue_to_backlog, struct sk_buff *skb, int cpu,
	     unsigned int *qtail, int ret)
#endif
{
	struct bpftune_event event =  { 0 };
	long old[3], new[3];
	int max_backlog, *max_backlogp = (int *)&netdev_max_backlog;
	__u64 time, cpubit;

	/* a high-frequency event so bail early if we can... */
	if (ret != NET_RX_DROP)
		return 0;

	drop_count++;

	/* only sample subset of drops to reduce overhead. */
	if ((drop_count % 16) != 0)
		return 0;
	if (bpf_probe_read_kernel(&max_backlog, sizeof(max_backlog),
				  max_backlogp))
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
	if (drop_count < (max_backlog >> 4))
		return 0;

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
	return 0;
}
