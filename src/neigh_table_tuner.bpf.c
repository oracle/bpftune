/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

SEC("tp_btf/neigh_create")
int BPF_PROG(handle_neigh_create, struct neigh_table *tbl,
	     struct net_device *dev, const void *pkey,
	     struct neighbour *n, bool exempt_from_gc)
{
	struct bpftune_event event = {};

	/* exempt from gc entries are not subject to space constraints */
	if (exempt_from_gc)
		return 0;

	__bpf_printk("adding neighbour entry");

	event.tuner_id = tuner_id;
	bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
