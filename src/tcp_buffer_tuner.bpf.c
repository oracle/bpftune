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
#include "tcp_buffer_tuner.h"
#include <bpftune/corr.h>

BPF_MAP_DEF(corr_map, BPF_MAP_TYPE_HASH, struct corr_key, struct corr, 1024);

bool under_memory_pressure = false;
bool near_memory_pressure = false;
bool near_memory_exhaustion = false;
/* use global tcp sock count since tcp memory pressure/exhaustion are
 * computed as fraction of total system memory.
 */
__s64 tcp_sock_count = 0;
__s64 tcp_max_sock_count = 0;

/* set from userspace */
int kernel_page_size;
int kernel_page_shift;
int sk_mem_quantum;
int sk_mem_quantum_shift;
unsigned long nr_free_buffer_pages;

#define tcp_tunable_corr(__id, __cookie, __newval, __tp, __field_type, __field)\
	{								\
		__field_type __field;					\
		if (!bpf_probe_read_kernel(&__field, sizeof(__field),	\
			__builtin_preserve_access_index(&tp->__field)))	\
			corr_update_bpf(&corr_map, __id, __cookie,	\
					__newval, __field);		\
	}

static __always_inline bool tcp_nearly_out_of_memory(struct sock *sk,
						     struct bpftune_event *event)
{
	long limit_sk_mem_quantum[3] = { };
	long allocated;
	long mem[3] = { }, mem_new[3] = { };
	struct net *net = BPF_CORE_READ(sk, sk_net.net);
	struct proto *prot = BPF_CORE_READ(sk, sk_prot);
	atomic_long_t *memory_allocated = BPF_CORE_READ(prot, memory_allocated);
	long *sysctl_mem = BPF_CORE_READ(prot, sysctl_mem);
	__u8 shift_left = 0, shift_right = 0;
	int i;

	if (!sk || !prot || !memory_allocated)
		return false;
	allocated = BPF_CORE_READ(memory_allocated, counter);
	if (!allocated)
		return false;
	if (bpf_probe_read_kernel(mem, sizeof(mem), sysctl_mem))
		return false;

	if (!mem[0] || !mem[1] || !mem[2])
		return false;

	if (kernel_page_shift >= sk_mem_quantum_shift) {
		shift_left = kernel_page_shift - sk_mem_quantum_shift;
		if (shift_left >= 32)
			return false;
	} else if (sk_mem_quantum_shift > kernel_page_shift) {
		shift_right = sk_mem_quantum_shift - kernel_page_shift;
		if (shift_right >= 32)
			return false;
	}

	for (i = 0; i < 3; i++) {
		limit_sk_mem_quantum[i] = mem[i];
		if (shift_left)
			limit_sk_mem_quantum[i] <<= shift_left;
		if (shift_right)
			limit_sk_mem_quantum[i] >>= shift_right;
		if (limit_sk_mem_quantum[i] <= 0)
			return false;
	}

	if (NEARLY_FULL(allocated, limit_sk_mem_quantum[2])) {
		/* approaching memory exhaustion event; dial down wmem/rmem
 		 * buffer limits to limit per-socket costs.
		 */
		near_memory_exhaustion = true;
		near_memory_pressure = true;
		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		mem_new[2] = min(nr_free_buffer_pages >> 2,
				 BPFTUNE_GROW_BY_DELTA(mem[2]));
		/* if we still have room to grow mem exhaustion limit, do that,
		 * otherwise shrink wmem/rmem.
		 */
		if (mem_new[2] <= (nr_free_buffer_pages >> 2)) {
			send_sk_sysctl_event(sk, TCP_MEM_EXHAUSTION,
					     TCP_BUFFER_TCP_MEM, mem, mem_new,
					     event);
			return true;
		}
		if (!net)
			return true;
		mem[0] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[0]);
		mem[1] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[1]);
		mem[2] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[2]);
		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		mem_new[2] = BPFTUNE_SHRINK_BY_DELTA(mem[2]);
		send_sk_sysctl_event(sk, TCP_BUFFER_DECREASE,
				     TCP_BUFFER_TCP_WMEM,
				     mem, mem_new, event);
		if (!net)
			return true;
		mem[0] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[0]);
		mem[1] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[1]);
		mem[2] = (long)BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[2]);
		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		mem_new[2] = BPFTUNE_SHRINK_BY_DELTA(mem[2]);
		send_sk_sysctl_event(sk, TCP_BUFFER_DECREASE,
				     TCP_BUFFER_TCP_RMEM,
				     mem, mem_new, event);
		return true;
	} else if (NEARLY_FULL(allocated, limit_sk_mem_quantum[1])) {
		/* send approaching memory pressure event; we also increase
		 * memory exhaustion limit as it tends to lead to
		 * pathological tcp behaviour.  If min/memory pressure are
		 * less than ~8%,~12% of memory), bump them up too.
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
		send_sk_sysctl_event(sk, TCP_MEM_PRESSURE,
				     TCP_BUFFER_TCP_MEM, mem, mem_new,
				     event);
		near_memory_pressure = true;
		return true;
	}
	near_memory_exhaustion = false;
	near_memory_pressure = false;

	return false;
}

BPF_FENTRY(tcp_enter_memory_pressure, struct sock *sk)
{
	struct bpftune_event event = { 0 };

	(void) tcp_nearly_out_of_memory(sk, &event);
	return 0;
}

BPF_FENTRY(tcp_leave_memory_pressure, struct sock *sk)
{
	under_memory_pressure = false;
	return 0;
}

/* By instrumenting tcp_sndbuf_expand() we know the following, due to the
 * fact tcp_should_expand_sndbuf() has returned true:
 *
 * - the socket is not locked (SOCK_SNDBUF_LOCKED);
 * - we are not under global TCP memory pressure; and
 * - not under soft global TCP memory pressure; and
 * - we have not filled the congestion window.
 *
 * However, all that said, we may soon run out of sndbuf space, so
 * if it is nearly exhausted (>75% full), expand by 25%.
 */
BPF_FENTRY(tcp_sndbuf_expand, struct sock *sk)
{
	struct bpftune_event event = { 0 };
	struct net *net = BPF_CORE_READ(sk, sk_net.net);
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	long wmem[3], wmem_new[3];
	long sndbuf;

	if (!sk || !net || tcp_nearly_out_of_memory(sk, &event))
		return 0;

	sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
	wmem[2] = BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[2]);

	if (NEARLY_FULL(sndbuf, wmem[2])) {

		if (tcp_nearly_out_of_memory(sk, &event))
			return 0;

		if (!net)
			return 0;
		wmem[0] = wmem_new[0] = BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[0]);
		wmem[1] = wmem_new[1] = BPF_CORE_READ(net, ipv4.sysctl_tcp_wmem[1]);
		wmem_new[2] = BPFTUNE_GROW_BY_DELTA(wmem[2]);

		if (send_sk_sysctl_event(sk, TCP_BUFFER_INCREASE,
					 TCP_BUFFER_TCP_WMEM,
					 wmem, wmem_new, &event) < 0)
			return 0;
		/* correlate changes to wmem with round-trip time to spot
		 * cases where buffer increase is correlated with longer
		 * latencies.
		 */
		tcp_tunable_corr(TCP_BUFFER_TCP_WMEM, event.netns_cookie,
				 wmem[2], tp, __u32, srtt_us);
	}
	return 0;
}

/* sadly tcp_rcv_space_adjust() has checks internal to it so it is called
 * regardless of if we are under memory pressure or not; so use the variable
 * we set when memory pressure is triggered.
 */
BPF_FENTRY(tcp_rcv_space_adjust, struct sock *sk)
{
	struct bpftune_event event = { 0 };
	struct net *net = BPF_CORE_READ(sk, sk_net.net);
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	long rmem[3], rmem_new[3];
	__u8 sk_userlocks = 0;
	long rcvbuf;

	if (!sk || !net)
		return 0;

#ifndef BPFTUNE_LEGACY
	/* CO-RE does not support bitfields... */
	sk_userlocks = sk->sk_userlocks;
#endif
	if ((sk_userlocks & SOCK_RCVBUF_LOCK) || near_memory_pressure ||
	    near_memory_exhaustion)
		return 0;

	rcvbuf = BPF_CORE_READ(sk, sk_rcvbuf);
	rmem[2] = BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[2]);

	if (NEARLY_FULL(rcvbuf, rmem[2])) {
		if (tcp_nearly_out_of_memory(sk, &event))
			return 0;

		rmem[0] = rmem_new[0] = BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[0]);
		rmem[1] = rmem_new[1] = BPF_CORE_READ(net, ipv4.sysctl_tcp_rmem[1]);
		rmem_new[2] = BPFTUNE_GROW_BY_DELTA(rmem[2]);
		if (send_sk_sysctl_event(sk, TCP_BUFFER_INCREASE, TCP_BUFFER_TCP_RMEM,
					 rmem, rmem_new, &event) < 0)
			return 0;
		/* correlate changes to rmem with round-trip time to spot
		 * cases where buffer increase is correlated with longer
		 * latencies.
		 */
		tcp_tunable_corr(TCP_BUFFER_TCP_RMEM, event.netns_cookie,
				 rmem[2], tp, __u32, srtt_us);

	}
	return 0;
}

BPF_FENTRY(tcp_init_sock, struct sock *sk)
{
	struct bpftune_event event = { 0 };

	if (sk) {
		if (++tcp_sock_count > tcp_max_sock_count)
			tcp_max_sock_count = tcp_sock_count;
		(void) tcp_nearly_out_of_memory(sk, &event);
	}
	return 0;
}

BPF_FENTRY(tcp_release_cb, struct sock *sk)
{
	if (tcp_sock_count > 0)
		tcp_sock_count--;
	return 0;
}
