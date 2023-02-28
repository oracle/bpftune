/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "neigh_table_tuner.h"

BPF_MAP_DEF(tbl_map, BPF_MAP_TYPE_HASH, __u64, struct tbl_stats, 1024);

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
		event.tuner_id = tuner_id;
		event.scenario_id = NEIGH_TABLE_FULL;
		if (n->parms && n->parms->net.net)
			event.netns_cookie = get_netns_cookie(n->parms->net.net);
		__builtin_memcpy(&event.raw_data, tbl_stats, sizeof(*tbl_stats));
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	}
	return 0;
}

