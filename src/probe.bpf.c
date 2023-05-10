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
#include "netns_tuner.h"

/* probe hash map */
BPF_MAP_DEF(probe_hash_map, BPF_MAP_TYPE_HASH, __u64, __u64, 65536);

/* probe kprobe/fentry */
BPF_FENTRY(setup_net, struct net *net, struct user_namespace *user_ns)
{
	return 0;
}

#ifdef BPFTUNE_LEGACY
SEC("raw_tracepoint/neigh_create")
#else
SEC("tp_btf/neigh_create")
#endif
int BPF_PROG(bpftune_neigh_create, struct neigh_table *tbl,
             struct net_device *dev, const void *pkey,
             struct neighbour *n, bool exempt_from_gc)
{
	return 0;
}

SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
        return 1;
}
