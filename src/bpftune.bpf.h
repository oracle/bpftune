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

/* from include/linux/log2.h */
/**
 * ilog2 - log of base 2 of 32-bit or a 64-bit unsigned value
 * @n - parameter
 *
 * constant-capable log of base 2 calculation
 * - this can be used to initialise global variables from constant data, hence
 *   the massive ternary operator construction
 *
 * selects the appropriately-sized optimised version depending on sizeof(n)
 */
#ifndef ilog2
#define ilog2(n)				\
(						\
		(n) < 2 ? 0 :			\
		(n) & (1ULL << 63) ? 63 :	\
		(n) & (1ULL << 62) ? 62 :	\
		(n) & (1ULL << 61) ? 61 :	\
		(n) & (1ULL << 60) ? 60 :	\
		(n) & (1ULL << 59) ? 59 :	\
		(n) & (1ULL << 58) ? 58 :	\
		(n) & (1ULL << 57) ? 57 :	\
		(n) & (1ULL << 56) ? 56 :	\
		(n) & (1ULL << 55) ? 55 :	\
		(n) & (1ULL << 54) ? 54 :	\
		(n) & (1ULL << 53) ? 53 :	\
		(n) & (1ULL << 52) ? 52 :	\
		(n) & (1ULL << 51) ? 51 :	\
		(n) & (1ULL << 50) ? 50 :	\
		(n) & (1ULL << 49) ? 49 :	\
		(n) & (1ULL << 48) ? 48 :	\
		(n) & (1ULL << 47) ? 47 :	\
		(n) & (1ULL << 46) ? 46 :	\
		(n) & (1ULL << 45) ? 45 :	\
		(n) & (1ULL << 44) ? 44 :	\
		(n) & (1ULL << 43) ? 43 :	\
		(n) & (1ULL << 42) ? 42 :	\
		(n) & (1ULL << 41) ? 41 :	\
		(n) & (1ULL << 40) ? 40 :	\
		(n) & (1ULL << 39) ? 39 :	\
		(n) & (1ULL << 38) ? 38 :	\
		(n) & (1ULL << 37) ? 37 :	\
		(n) & (1ULL << 36) ? 36 :	\
		(n) & (1ULL << 35) ? 35 :	\
		(n) & (1ULL << 34) ? 34 :	\
		(n) & (1ULL << 33) ? 33 :	\
		(n) & (1ULL << 32) ? 32 :	\
		(n) & (1ULL << 31) ? 31 :	\
		(n) & (1ULL << 30) ? 30 :	\
		(n) & (1ULL << 29) ? 29 :	\
		(n) & (1ULL << 28) ? 28 :	\
		(n) & (1ULL << 27) ? 27 :	\
		(n) & (1ULL << 26) ? 26 :	\
		(n) & (1ULL << 25) ? 25 :	\
		(n) & (1ULL << 24) ? 24 :	\
		(n) & (1ULL << 23) ? 23 :	\
		(n) & (1ULL << 22) ? 22 :	\
		(n) & (1ULL << 21) ? 21 :	\
		(n) & (1ULL << 20) ? 20 :	\
		(n) & (1ULL << 19) ? 19 :	\
		(n) & (1ULL << 18) ? 18 :	\
		(n) & (1ULL << 17) ? 17 :	\
		(n) & (1ULL << 16) ? 16 :	\
		(n) & (1ULL << 15) ? 15 :	\
		(n) & (1ULL << 14) ? 14 :	\
		(n) & (1ULL << 13) ? 13 :	\
		(n) & (1ULL << 12) ? 12 :	\
		(n) & (1ULL << 11) ? 11 :	\
		(n) & (1ULL << 10) ? 10 :	\
		(n) & (1ULL <<  9) ?  9 :	\
		(n) & (1ULL <<  8) ?  8 :	\
		(n) & (1ULL <<  7) ?  7 :	\
		(n) & (1ULL <<  6) ?  6 :	\
		(n) & (1ULL <<  5) ?  5 :	\
		(n) & (1ULL <<  4) ?  4 :	\
		(n) & (1ULL <<  3) ?  3 :	\
		(n) & (1ULL <<  2) ?  2 :	\
		1 )
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

#define SECOND	((__u64)1000000000)

#define HOUR	(3600 * SECOND)

/* 75% full */
#define NEARLY_FULL(val, limit)	\
	((val) >= ((limit) - ((limit) >> 2)))

static __always_inline long get_netns_cookie(struct net *net)
{
	return net->net_cookie;
}
