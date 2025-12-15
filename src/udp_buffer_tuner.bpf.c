/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2025, Oracle and/or its affiliates.
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
#include "udp_buffer_tuner.h"
#include <bpftune/corr.h>

bool under_memory_pressure = false;
bool near_memory_pressure = false;
bool near_memory_exhaustion = false;

/* set from userspace */
int kernel_page_size;
int kernel_page_shift;
int sk_mem_quantum;
int sk_mem_quantum_shift;
unsigned long long nr_free_buffer_pages;

long long rmem_max, rmem_default;

struct bpftune_sample udp_fail_rcv_sample = { };

static __always_inline bool udp_nearly_out_of_memory(struct sock *sk,
						     struct bpftune_event *event)
{
	long limit_sk_mem_quantum[3] = { };
	long allocated;
	long mem[3] = { }, mem_new[3] = { };
	struct proto *prot = BPFTUNE_CORE_READ(sk, sk_prot);
	atomic_long_t *memory_allocated = BPFTUNE_CORE_READ(prot, memory_allocated);
	long *sysctl_mem = BPFTUNE_CORE_READ(prot, sysctl_mem);
	__s8 shift = 0;
	struct net *net;
	int i;

	if (!sk || !prot || !memory_allocated)
		return false;
	net = BPFTUNE_CORE_READ(sk, sk_net.net);
	if (!net)
		return 0;

	allocated = BPFTUNE_CORE_READ(memory_allocated, counter);
	if (!allocated)
		return false;
	if (bpf_probe_read_kernel(mem, sizeof(mem), sysctl_mem))
		return false;

	if (!mem[0] || !mem[1] || !mem[2])
		return false;

	if (LINUX_KERNEL_VERSION < KERNEL_VERSION(5, 16, 0)) {
		/* we are on v5.15 or earlier; mem quantum is used
		 * to shift limits.
		 */
		shift = sk_mem_quantum_shift - kernel_page_shift;
		if (shift >= 32 || shift <= -32)
			return false;
	}

	for (i = 0; i < 3; i++) {
		limit_sk_mem_quantum[i] = mem[i];
		if (shift > 0)
			limit_sk_mem_quantum[i] >>= shift;
		else if (shift < 0)
			limit_sk_mem_quantum[i] <<= -shift;

		if (limit_sk_mem_quantum[i] <= 0)
			return false;
	}

	if (NEARLY_FULL(allocated, limit_sk_mem_quantum[2])) {
		/* approaching memory exhaustion event; dial down mem/rmem
 		 * buffer limits to limit per-socket costs.
		 */
		near_memory_exhaustion = true;
		near_memory_pressure = true;
		if (mem[0] < nr_free_buffer_pages >> 4)
			mem_new[0] = BPFTUNE_GROW_BY_DELTA(mem[0]);
		if (mem[1] < nr_free_buffer_pages >> 3)
			mem_new[1] = BPFTUNE_GROW_BY_DELTA(mem[1]);
		mem_new[2] = min(nr_free_buffer_pages >> 2,
				 BPFTUNE_GROW_BY_DELTA(mem[2]));
		/* if we still have room to grow mem exhaustion limit, do that,
		 * otherwise shrink rmem.
		 */

		if (mem_new[2] <= (nr_free_buffer_pages >> 2)) {
			send_sk_sysctl_event(sk, UDP_MEM_EXHAUSTION,
					     UDP_BUFFER_UDP_MEM, mem, mem_new,
					     event);
			return true;
		}
		if (!net)
			return true;
		mem[0] = rmem_max;
		mem_new[0] = BPFTUNE_SHRINK_BY_DELTA(mem[0]);
		if (mem_new[0] > UDP_BUFFER_MIN)
			send_sk_sysctl_event(sk, UDP_BUFFER_DECREASE,
					     UDP_BUFFER_NET_CORE_RMEM_MAX,
					     mem, mem_new, event);
		mem[0] = rmem_default;
		mem_new[0] = BPFTUNE_SHRINK_BY_DELTA(mem[0]);
		if (mem_new[0] > UDP_BUFFER_MIN)
			send_sk_sysctl_event(sk, UDP_BUFFER_DECREASE,
					     UDP_BUFFER_NET_CORE_RMEM_MAX,
					     mem, mem_new, event);
		return true;
	} else if (NEARLY_FULL(allocated, limit_sk_mem_quantum[1])) {
		/* approaching memory pressure event. If min/memory pressure
		 * are less than ~8%,~12% of memory), bump them up too.
		 * Mem exhaustion maxes out at 25% of memory.
		 */
		if (!mem[0] || !mem[1] || !mem[2])
			return false;

		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		if (mem[0] < nr_free_buffer_pages >> 4)
			mem_new[0] = BPFTUNE_GROW_BY_DELTA(mem[0]);
		if (mem[1] < nr_free_buffer_pages >> 3)
			mem_new[1] = BPFTUNE_GROW_BY_DELTA(mem[1]);
		mem_new[2] = min(nr_free_buffer_pages >> 2,
				 BPFTUNE_GROW_BY_DELTA(mem[2]));
		send_sk_sysctl_event(sk, UDP_MEM_PRESSURE,
				     UDP_BUFFER_UDP_MEM, mem, mem_new,
				     event);
		near_memory_pressure = true;
		return true;
	}
	near_memory_exhaustion = false;
	near_memory_pressure = false;

	return false;
}

static __always_inline int udp_fail_rcv(int ret, struct sock *sk)
{
	struct bpftune_event event = { 0 };
	long rmem[3], rmem_new[3];
	int rcvbuf;
	int id;

	if (!sk)
		return 0;
	switch (ret) {
	case -ENOBUFS:
		if (udp_nearly_out_of_memory(sk, &event))
			return 0;
		return 0;

	case -ENOMEM:
		/* even if rmem_max is set to a high value, the socket in
		 * question may have an sk_rcvbuf value that is lower;
		 * in such cases, the losses incurred should not inform
		 * an rmem_max increase.  However if the rcvbuf size is
		 * approximate to rmem_default, increase that.  Note that
		 * if these increases succeeds, the same socket cannot drive
		 * future increases since the relevant rmem_* value is
		 * now out of range of the static rcvbuf value.
		 */
		rcvbuf = BPFTUNE_CORE_READ(sk, sk_rcvbuf);
		if (BPFTUNE_WITHIN_BITSHIFT(rcvbuf, rmem_max, 2)) {
			rmem[0] = rmem_max;
			rmem_new[0] = BPFTUNE_GROW_BY_DELTA(rmem_max);
			id = UDP_BUFFER_NET_CORE_RMEM_MAX;
		} else if (BPFTUNE_WITHIN_BITSHIFT(rcvbuf, rmem_default, 2)) {
			__u8 sk_userlocks = 0;

			rmem[0] = rmem_default;
			rmem_new[0] = BPFTUNE_GROW_BY_DELTA(rmem_default);
			id = UDP_BUFFER_NET_CORE_RMEM_DEFAULT;
			/* sk_userlocks is a bitfield prior to 6.9 */
			if (LINUX_KERNEL_VERSION < KERNEL_VERSION(6, 9, 0)) {
#ifndef BPFTUNE_LEGACY
#ifdef BPF_CORE_READ_BITFIELD
				sk_userlocks = BPF_CORE_READ_BITFIELD(sk, sk_userlocks);
#else
				sk_userlocks = 0;
#endif
#endif
			} else {
				sk_userlocks = BPFTUNE_CORE_READ(sk, sk_userlocks);
			}
			/* buffer locked; ignore since rmem_default updates
			 * will not help; rmem_max updates will since they
			 * increase the max value specifiable via setsockopt.
			 */
			if (sk_userlocks & SOCK_RCVBUF_LOCK)
				return 0;
		} else {
			return 0;
		}
		if (rmem_new[0] >= UDP_BUFFER_MAX)
			return 0;

		send_sk_sysctl_event(sk, UDP_BUFFER_INCREASE, id,
				     rmem, rmem_new, &event);
		return 0;
	default:
		return 0;
	}
}

#ifdef BPFTUNE_LEGACY
SEC("raw_tracepoint/udp_fail_queue_rcv_skb")
#else
SEC("tp_btf/udp_fail_queue_rcv_skb")
#endif
int BPF_PROG(bpftune_udp_fail_rcv, int ret, struct sock *sk)
{
	if (ret == 0)
		return 0;
	/* only sample subset of events to reduce overhead. */
	if (ret != -ENOBUFS)
		bpftune_sample(udp_fail_rcv_sample);

	return udp_fail_rcv(ret, sk);
}

#define SK_MEM_RECV 1

#ifdef BPFTUNE_LEGACY
SEC("raw_tracepoint/sock_exceed_buf_limit")
#else
SEC("tp_btf/sock_exceed_buf_limit")
#endif
int BPF_PROG(bpftune_sock_exceed_buf_limit, struct sock *sk, struct proto *prot,
	     long allocated, int kind)
{
	if (kind == SK_MEM_RECV) {
		__u16 proto = BPFTUNE_CORE_READ(sk, sk_protocol);

		if (proto == IPPROTO_UDP)
			return udp_fail_rcv(-ENOBUFS, sk);
	}
	return 0;
}
