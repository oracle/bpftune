/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "neigh_table_tuner.h"

BPF_MAP_DEF(tbl_map, BPF_MAP_TYPE_HASH, __u64, struct tbl_stats, 1024);

int ncpus;

#ifdef BPFTUNE_LEGACY
SEC("raw_tracepoint/neigh_create")
int BPF_PROG(bpftune_neigh_create, struct neigh_table *tbl,
	     struct net_device *dev, const void *pkey,
	     struct neighbour *n, bool exempt_from_gc)
#else
SEC("tp_btf/neigh_create")
int BPF_PROG(bpftune_neigh_create, struct neigh_table *tbl,
	     struct net_device *dev, const void *pkey,
	     struct neighbour *n, bool exempt_from_gc)
#endif
{
	
	struct tbl_stats *tbl_stats;
	struct bpftune_event event = {};
	__u64 key = (__u64)tbl;

	tbl_stats = bpf_map_lookup_elem(&tbl_map, &key);

	if (!tbl_stats) {
		struct tbl_stats new_tbl_stats = {};

		new_tbl_stats.family = BPF_CORE_READ(tbl, family);
		new_tbl_stats.entries = BPF_CORE_READ(tbl, entries.counter);
		new_tbl_stats.max = BPF_CORE_READ(tbl, gc_thresh3);
		if (dev) {
			bpf_probe_read(&new_tbl_stats.dev, sizeof(new_tbl_stats.dev), dev);
			new_tbl_stats.ifindex = BPF_CORE_READ(dev, ifindex);
		}
		bpf_map_update_elem(&tbl_map, &key, &new_tbl_stats, BPF_ANY);
		tbl_stats = bpf_map_lookup_elem(&tbl_map, &key);
		if (!tbl_stats)
			return 0;
	}
	tbl_stats->entries = BPF_CORE_READ(tbl, entries.counter);
	tbl_stats->gc_entries = BPF_CORE_READ(tbl, gc_entries.counter);
	tbl_stats->max = BPF_CORE_READ(tbl, gc_thresh3);

	/* exempt from gc entries are not subject to space constraints, but
 	 * do take up table entries.
 	 */
	if (NEARLY_FULL(tbl_stats->entries, tbl_stats->max)) {
		struct neigh_parms *parms = BPF_CORE_READ(n, parms);
		struct net *net = BPF_CORE_READ(parms, net.net);

		event.tuner_id = tuner_id;
		event.scenario_id = NEIGH_TABLE_FULL;
		if (net) {
			event.netns_cookie = get_netns_cookie(net);
			if (event.netns_cookie < 0)
				return 0;
		}
		__builtin_memcpy(&event.raw_data, tbl_stats, sizeof(*tbl_stats));
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	}
	return 0;
}

/* forced gc is a signal that ipv6 route table space is low. */
BPF_FENTRY(fib6_run_gc, unsigned long expires, struct net *net, bool force)
{
	long max_size;

	if (force) {
		struct bpftune_event event = {};
		long old[3] = {};
		long new[3] = {};
		long max_size = BPF_CORE_READ(net, ipv6.sysctl.ip6_rt_max_size);

		event.tuner_id = tuner_id;
		event.scenario_id = DST_TABLE_FULL;

		old[0] = max_size;
		new[0] = BPFTUNE_GROW_BY_DELTA(max_size);
		if (send_net_sysctl_event(net, DST_TABLE_FULL,
					  NEIGH_TABLE_IPV6_MAX_SIZE,
					  old, new, &event) < 0)
			return 0;
	}
	return 0;
}

BPF_FENTRY(ip6_dst_alloc, struct net *net, struct net_device *dev,
			  int flags)
{
	__s64 total = BPF_CORE_READ(net, ipv6.ip6_dst_ops.pcpuc_entries.count);
	long max_size = BPF_CORE_READ(net, ipv6.sysctl.ip6_rt_max_size);

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 15, 0)) {
		s32 *counters = BPF_CORE_READ(net, ipv6.ip6_dst_ops.pcpuc_entries.counters);
		long i;
		for (i = 0; i < ncpus; i++) {
			__s32 *countp = BPF_CORE_READ(net->ipv6.ip6_dst_ops.pcpuc_entries.counters, i);
			total += *countp;
		}
	}
	__bpf_printk("dst alloc count %d max %d\n", total, max_size);

	return 0;
}
