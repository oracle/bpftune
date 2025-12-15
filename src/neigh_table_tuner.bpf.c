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
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <bpftune/bpftune.bpf.h>
#include "neigh_table_tuner.h"

BPF_MAP_DEF(tbl_map, BPF_MAP_TYPE_HASH, __u64, struct tbl_stats, 1024, 0);

#ifdef BPFTUNE_LEGACY
SEC("raw_tracepoint/neigh_create")
#else
SEC("tp_btf/neigh_create")
#endif
int BPF_PROG(bpftune_neigh_create, struct neigh_table *tbl,
	     struct net_device *dev, const void *pkey,
	     struct neighbour *n, bool exempt_from_gc)
{
	
	struct tbl_stats *tbl_stats;
	struct bpftune_event event = {};
	__u64 key = (__u64)tbl;

	tbl_stats = bpf_map_lookup_elem(&tbl_map, &key);

	if (!tbl_stats) {
		struct tbl_stats new_tbl_stats = {};

		new_tbl_stats.family = BPFTUNE_CORE_READ(tbl, family);
		new_tbl_stats.entries = BPFTUNE_CORE_READ(tbl, entries.counter);
		new_tbl_stats.thresh1 = BPFTUNE_CORE_READ(tbl, gc_thresh1);
		new_tbl_stats.thresh2 = BPFTUNE_CORE_READ(tbl, gc_thresh2);
		new_tbl_stats.max = BPFTUNE_CORE_READ(tbl, gc_thresh3);

		if (dev) {
			new_tbl_stats.dev[0] = '\0';
			BPFTUNE_CORE_READ_STR_INTO(&new_tbl_stats.dev, dev, name);
			new_tbl_stats.ifindex = BPFTUNE_CORE_READ(dev, ifindex);
		}
		bpf_map_update_elem(&tbl_map, &key, &new_tbl_stats, BPF_ANY);
		tbl_stats = bpf_map_lookup_elem(&tbl_map, &key);
		if (!tbl_stats)
			return 0;
	}
	tbl_stats->entries = BPFTUNE_CORE_READ(tbl, entries.counter);
	tbl_stats->gc_entries = BPFTUNE_CORE_READ(tbl, gc_entries.counter);
	tbl_stats->thresh1 = BPFTUNE_CORE_READ(tbl, gc_thresh1);
	tbl_stats->thresh2 = BPFTUNE_CORE_READ(tbl, gc_thresh2);
	tbl_stats->max = BPFTUNE_CORE_READ(tbl, gc_thresh3);

	/* exempt from gc entries are not subject to space constraints, but
 	 * do take up table entries.
 	 */
	if (NEARLY_FULL(tbl_stats->entries, tbl_stats->max)) {
		struct neigh_parms *parms = BPFTUNE_CORE_READ(n, parms);
		struct net *net = BPFTUNE_CORE_READ(parms, net.net);

		event.tuner_id = tuner_id;
		event.scenario_id = NEIGH_TABLE_FULL;
		if (net) {
			event.netns_cookie = get_netns_cookie(net);
			if (event.netns_cookie < 0)
				return 0;
		}
		STATIC_ASSERT(sizeof(event.raw_data) >= sizeof(*tbl_stats),
			      "event.raw_data too small");
		__builtin_memcpy(&event.raw_data, tbl_stats, sizeof(*tbl_stats));
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	}
	return 0;
}
