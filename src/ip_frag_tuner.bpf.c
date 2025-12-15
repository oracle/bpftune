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
#include "ip_frag_tuner.h"
#include <bpftune/corr.h>

static __always_inline int defrag(struct net *net, struct fqdir *fqdir,
				  struct ipstats_mib *mib, int tunable)
{
	long mem = BPFTUNE_CORE_READ(fqdir, mem.counter);
	long high_thresh = BPFTUNE_CORE_READ(fqdir, high_thresh);

	bpftune_debug("defrag: mem %ld high thresh %ld\n",
			mem, high_thresh);
	if (!fqdir || !mem || !high_thresh)
		return 0;

	/* do not raise limits when we see a correlation between raised fragment
	 * threshold and fragmentation failures; this suggests DoS
	 */
	if (NEARLY_FULL(mem, high_thresh)) {
		struct bpftune_event event = { 0 };
		long old[3] = {};
		long new[3] = {};	

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
	struct ipstats_mib *mib = BPFTUNE_CORE_READ(net, mib.ip_statistics);

	if (!fqdir)
		return 0;
	return defrag(net, fqdir, mib, IP_FRAG_MAX_THRESHOLD);
}

#define SKB_DST_NOREF	1UL
#define SKB_DST_PTRMASK	~(SKB_DST_NOREF)
BPF_FENTRY(ipv6_frag_rcv, struct sk_buff *skb)
{
	long unsigned int refdst = BPFTUNE_CORE_READ(skb, _skb_refdst);
	struct dst_entry *dst = (struct dst_entry *)(refdst & SKB_DST_PTRMASK);
	struct ipstats_mib *mib;
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
	mib = BPFTUNE_CORE_READ(net, mib.ipv6_statistics);
	if (!mib)
		return 0;
	return defrag(net, fqdir, mib, IP6_FRAG_MAX_THRESHOLD);
}
