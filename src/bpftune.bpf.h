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

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 64 * 1024);
} ringbuf_map SEC(".maps");

struct remote_host {
	__u64 retransmits;
	__u64 last_retransmit;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct in6_addr);
	__type(value, struct remote_host);
} remote_host_map SEC(".maps");

unsigned int tuner_id;

#ifndef SO_SNDBUF
#define SO_SNDBUF       	7
#endif
#ifndef SO_RCVBUF
#define SO_RCVBUF       	8
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

#ifndef s6_addr32
#define s6_addr32		in6_u.u6_addr32
#endif

#ifndef TCP_CA_NAME_MAX
#define TCP_CA_NAME_MAX		16
#endif
static __always_inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return (
		(unsigned long)(a->s6_addr32[0] | a->s6_addr32[1]) |
		(unsigned long)(a->s6_addr32[2] ^
				bpf_htonl(0x0000ffff))) == 0UL;
}

static __always_inline int tcpbpf_set_key(struct bpf_sock_ops *ops,
                                          struct in6_addr *key)
{
	__u32 *key_raddr = (__u32 *)key;

	__builtin_memset(key, 0, sizeof(*key));

	/* NB; the order of assignment matters here. Why? Because
	 * the BPF verifier will optimize a load of two adjacent
	 * __u32s as a __u64 load; and the verifier will duly
	 * complain since it verifies that loads for various fields
	 * are only 32 bits in size.
	 */
	switch (ops->family) {
	case AF_INET6:
		/* check for v4mapped */
                if (ipv6_addr_v4mapped((struct in6_addr *)&ops->local_ip6))
			goto v4mapped;
                key_raddr[3] = ops->remote_ip6[3];
		key_raddr[1] = ops->remote_ip6[1];
		key_raddr[0] = ops->remote_ip6[0];
                key_raddr[2] = ops->remote_ip6[2];
                break;
	case AF_INET:
v4mapped:
		key_raddr[0] = ops->remote_ip4;
		break;
default:
		return -EINVAL;
	}

	return 0;
}

#define SECOND	((__u64)1000000000)

#define HOUR	(3600 * SECOND)

#define RETRANSMIT_THRESH	10

/* If we retransmitted to this host in the last hour, we've surpassed
 * retransmit threshold.
 */
static __always_inline bool
remote_host_retransmit_threshold(struct remote_host *remote_host)
{
	__u64 now;

	if (remote_host->retransmits < RETRANSMIT_THRESH)
		return false;

	now = bpf_ktime_get_ns();

	if (now - remote_host->last_retransmit < HOUR)
		return true;

	remote_host->retransmits = 0;

	return false;
}

static void remote_host_retransmit(struct remote_host *remote_host)
{
	remote_host->retransmits++;
	remote_host->last_retransmit = bpf_ktime_get_ns();
}
