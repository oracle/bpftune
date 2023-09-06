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
#include "ip_frag_tuner.h"

/* ratio of failure to success is > 1/2 */
#define REASM_FAIL_THRESHOLD(success, fail)	((success >= 2) && (fail > (success >> 1)))

static __always_inline int defrag(struct net *net, struct fqdir *fqdir,
				  struct ipstats_mib *ip_stats, int tunable)
{
	long mem = BPFTUNE_CORE_READ(fqdir, mem.counter);
	long high_thresh = BPFTUNE_CORE_READ(fqdir, high_thresh);

	bpftune_debug("defrag: mem %ld high thresh %ld\n",
			mem, high_thresh);
	if (!fqdir || !mem || !high_thresh)
		return 0;

	/* FragmentSmack DoS relied on small packets overwhelming defragmentation;
	 * do not raise limits when we see small fragments and a significant
	 * number of fragmentation reassembly failures versus successes.
	 */
	if (NEARLY_FULL(mem, high_thresh)) {
		__u64 reasm_success = BPFTUNE_CORE_READ(ip_stats,
							mibs[IPSTATS_MIB_REASMOKS]);
		__u64 reasm_fails = BPFTUNE_CORE_READ(ip_stats,
						      mibs[IPSTATS_MIB_REASMFAILS]);
		struct bpftune_event event = { 0 };
		long old[3] = {};
		long new[3] = {};	

		bpftune_debug("nearly full, reasm success %ld reasm fail %ld\n",
				reasm_success, reasm_fails);

		/* too many fragmentation reassembly fails? */
		if (REASM_FAIL_THRESHOLD(reasm_success, reasm_fails))
			return 0;
		old[0] = high_thresh;
		new[0] = BPFTUNE_GROW_BY_DELTA(high_thresh);
		send_net_sysctl_event(net, IP_FRAG_THRESHOLD_INCREASE,
				      tunable,
				      old, new, &event);
	}
	return 0;
}

BPF_FENTRY(ip_defrag, struct net *net, struct sk_buff *skb, u32 user)
{
        struct fqdir *fqdir = BPFTUNE_CORE_READ(net, ipv4.fqdir);
	struct ipstats_mib *ip_stats;

	if (!fqdir)
		return 0;
	ip_stats = BPFTUNE_CORE_READ(net, mib.ip_statistics);

	if (!ip_stats)
		return 0;
	return defrag(net, fqdir, ip_stats, IP_FRAG_MAX_THRESHOLD);
}

#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
BPF_FENTRY(ipv6_frag_rcv, struct sk_buff *skb)
{
	long unsigned int refdst = BPFTUNE_CORE_READ(skb, _skb_refdst);
	struct dst_entry *dst = (struct dst_entry *)(refdst & SKB_DST_PTRMASK);
	struct ipstats_mib *ipv6_stats;
	struct net_device *dev;
	struct fqdir *fqdir;
	struct net *net;

	if (!dst)
		return 0;
	dev = BPFTUNE_CORE_READ(dst, dev);
	if (!dev)
		return 0;
	net = BPFTUNE_CORE_READ(dev, nd_net.net);
	if (!net)
		return 0;
	fqdir = BPFTUNE_CORE_READ(net, ipv6.fqdir);
	if (!fqdir)
		return 0;
	ipv6_stats = BPFTUNE_CORE_READ(net, mib.ipv6_statistics);
	if (!ipv6_stats)
		return 0;
	return defrag(net, fqdir, ipv6_stats, IP6_FRAG_MAX_THRESHOLD);
}
