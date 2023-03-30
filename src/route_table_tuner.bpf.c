/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "route_table_tuner.h"

struct dst_net {
	struct net *net;
};

BPF_MAP_DEF(dst_net_map, BPF_MAP_TYPE_HASH, __u64, __u64, 65536);

SEC("kprobe/ip6_dst_alloc")
int BPF_KPROBE(bpftune_ip6_dst_alloc_entry, struct net *net,
					    struct net_device *dev,
					    int flags)
{
	save_entry_data(dst_net_map, dst_net, net, net);
	return 0;
}

/* catch dst alloc failures and increase route table max size */
SEC("kretprobe/ip6_dst_alloc")
int BPF_KRETPROBE(bpftune_ip6_dst_alloc_return, struct rt6_info *dst)
{
	struct net *net;

	__bpf_printk("dst_alloc: %ld\n", dst);
	if (dst)
		return 0;

	get_entry_data(dst_net_map, dst_net, net, net);
	if (net) {
		struct bpftune_event event = {};
		long old[3] = {};
		long new[3] = {};
		long max_size;

		max_size = BPF_CORE_READ(net, ipv6.sysctl.ip6_rt_max_size);

		event.tuner_id = tuner_id;
		event.scenario_id = ROUTE_TABLE_FULL;

		old[0] = max_size;
		new[0] = BPFTUNE_GROW_BY_DELTA(max_size);
		if (send_net_sysctl_event(net, ROUTE_TABLE_FULL,
					  ROUTE_TABLE_IPV6_MAX_SIZE,
					  old, new, &event) < 0)
			return 0;
	}
	return 0;
}
