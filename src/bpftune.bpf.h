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
#define sk_net			__sk_common.skc_net

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

