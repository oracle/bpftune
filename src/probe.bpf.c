/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

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
	return 0;
}

SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
        return 1;
}
