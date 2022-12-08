/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#define __x86_64__
#include <errno.h>

#include "bpftune.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define DEBUG
/* don't want __bpf_printk()s slipping into production... */
#ifndef DEBUG
#undef __bpf_printk
#define __bpf_printk(...)
#endif

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 64 * 1024);
} ringbuf_map SEC(".maps");

unsigned int tuner_id;

/* TCP buffer tuning */
#ifndef SO_SNDBUF
#define SO_SNDBUF       	7
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF       	8
#endif

#ifndef SOCK_SNDBUF_LOCK
#define SOCK_SNDBUF_LOCK	1
#endif
#ifndef SOCK_RCVBUF_LOCK
#define SOCK_RCVBUF_LOCK	2
#endif

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM		4096
#endif
#ifndef SK_MEM_QUANTUM_SHIFT
#define SK_MEM_QUANTUM_SHIFT	ilog2(SK_MEM_QUANTUM)
#endif

#ifndef SOL_TCP
#define SOL_TCP        		6
#endif

#ifndef TCP_CONGESTION
#define TCP_CONGESTION		13
#endif

#ifndef AF_INET
#define AF_INET			2
#endif
#ifndef AF_INET6
#define AF_INET6		10
#endif

#define sk_family		__sk_common.skc_family
#define sk_rmem_alloc		sk_backlog.rmem_alloc
#define sk_state		__sk_common.skc_state
#define sk_daddr		__sk_common.skc_daddr
#define sk_v6_daddr		__sk_common.skc_v6_daddr
#define sk_net			__sk_common.skc_net
#define sk_prot			__sk_common.skc_prot

#ifndef s6_addr32
#define s6_addr32		in6_u.u6_addr32
#endif

/* TCP congestion algorithm tuning */
#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX		16
#endif

/* neigh table tuning */
#ifndef NUD_PERMANENT
#define NUD_PERMANENT	0x80
#endif
#ifndef NTF_EXT_LEARNED
#define NTF_EXT_LEARNED	0x10
#endif

static __always_inline long get_netns_cookie(struct net *net)
{
	return net ? net->net_cookie : 0;
}

static __always_inline void send_sysctl_event(struct sock *sk,
					      int scenario_id, int event_id,
					      long *old, long *new,
					      struct bpftune_event *event)
{
	struct net *net = sk ? sk->sk_net.net : 0;

	event->tuner_id = tuner_id;
	event->scenario_id = scenario_id;
	event->netns_cookie = net ? get_netns_cookie(net) : 0;
	event->update[0].id = event_id;
	event->update[0].old[0] = old[0];
	event->update[0].old[1] = old[1];
	event->update[0].old[2] = old[2];
	event->update[0].new[0] = new[0];
	event->update[0].new[1] = new[1];
	event->update[0].new[2] = new[2];
	bpf_ringbuf_output(&ringbuf_map, event, sizeof(*event), 0);
}


char _license[] SEC("license") = "Dual BSD/GPL";
