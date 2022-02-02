/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include "bpftune.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 512,
};

unsigned int tuner_id;

SEC("tp_btf/neigh_create")
int BPF_PROG(struct neigh_table *tbl, struct net_device *dev,
	     const void *pkey, struct neighbour *n, bool exempt_from_gc)
{
	struct bpftune_event event = {};

	/* exempt from gc entries are not subject to space constraints */
	if (exempt_from_gc)
		return 0;

	__bpf_printk("adding neighbour entry");

	event.tuner_id = tuner_id;
	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &event,
			      sizeof(event));

	return 0;
}
