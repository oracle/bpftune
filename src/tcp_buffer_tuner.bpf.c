/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "tcp_buffer_tuner.h"

bool under_memory_pressure = false;
bool near_memory_exhaustion = false;

long page_size = 4096;
long page_shift = 12;

static __always_inline bool tcp_nearly_out_of_memory(struct sock *sk)
{
	long allocated, limit_sk_mem_quantum = 0;

	if (!sk->sk_prot)
		return false;

	allocated = sk->sk_prot->memory_allocated->counter;
	if (bpf_probe_read(&limit_sk_mem_quantum,
			   sizeof(limit_sk_mem_quantum),
			   sk->sk_prot->sysctl_mem + 2) ||
			   !limit_sk_mem_quantum)
		return 0;
				
	if (page_size > SK_MEM_QUANTUM)
		limit_sk_mem_quantum <<= page_shift - SK_MEM_QUANTUM_SHIFT;
	else if (page_size < SK_MEM_QUANTUM)
		limit_sk_mem_quantum >>= SK_MEM_QUANTUM_SHIFT - page_shift;

	//__bpf_printk("allocated %ld, memory pressure %ld\n", allocated, limit_sk_mem_quantum);

	near_memory_exhaustion = NEARLY_FULL(allocated, limit_sk_mem_quantum);

	return near_memory_exhaustion;
}

SEC("fentry/tcp_enter_memory_pressure")
int BPF_PROG(bpftune_enter_memory_pressure, struct sock *sk)
{
	under_memory_pressure = true;
	return 0;
}

SEC("fentry/tcp_leave_memory_pressure")
int BPF_PROG(bpftune_leave_memory_pressure, struct sock *sk)
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
SEC("fentry/tcp_sndbuf_expand")
int BPF_PROG(bpftune_sndbuf_expand, struct sock *sk)
{
	struct bpftune_event event = {};
	struct net *net = sk->sk_net.net;
	int sndbuf, wmem2;

	if (!sk || !net || under_memory_pressure || near_memory_exhaustion)
		return 0;

	sndbuf = sk->sk_sndbuf;
	wmem2 = net->ipv4.sysctl_tcp_wmem[2];

	if (NEARLY_FULL(sndbuf, wmem2)) {
		long wmem0 = net->ipv4.sysctl_tcp_wmem[0];
		long wmem1 = net->ipv4.sysctl_tcp_wmem[1];

		if (tcp_nearly_out_of_memory(sk))
			return 0;

		event.tuner_id = tuner_id;
		event.netns_cookie = get_netns_cookie(net);
		event.update[0].id = TCP_BUFFER_TCP_WMEM;
		event.update[0].old[0] = wmem0;
		event.update[0].new[0] = wmem0;
		event.update[0].old[1] = wmem1;
		event.update[0].new[1] = wmem1;
		event.update[0].old[2] = wmem2;
		event.update[0].new[2] = BPFTUNE_GROW_BY_QUARTER(wmem2);
		bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
	}
	return 0;
}

/* sadly tcp_rcv_space_adjust() has checks internal to it so it is called
 * regardless of if we are under memory pressure or not; so use the variable
 * we set when memory pressure is triggered.
 */
SEC("fentry/tcp_rcv_space_adjust")
int BPF_PROG(bpftune_rcvbuf_adjust, struct sock *sk)
{
	struct bpftune_event event = {};
	struct net *net = sk->sk_net.net;
	int rcvbuf, rmem2;

	if (!sk || !net)
		return 0;

	if ((sk->sk_userlocks & SOCK_RCVBUF_LOCK) || under_memory_pressure ||
	    near_memory_exhaustion)
		return 0;

	rcvbuf = sk->sk_rcvbuf;
	rmem2 = net->ipv4.sysctl_tcp_rmem[2];

	if (NEARLY_FULL(rcvbuf, rmem2)) {
		long rmem0 = net->ipv4.sysctl_tcp_rmem[0];
		long rmem1 = net->ipv4.sysctl_tcp_rmem[1];

		if (tcp_nearly_out_of_memory(sk))
			return 0;

		event.tuner_id = tuner_id;
		event.netns_cookie = get_netns_cookie(net);
		event.update[0].id = TCP_BUFFER_TCP_RMEM;
		event.update[0].old[0] = rmem0;
		event.update[0].new[0] = rmem0;
		event.update[0].old[1] = rmem1;
		event.update[0].new[1] = rmem1;
		event.update[0].old[2] = rmem2;
		event.update[0].new[2] = BPFTUNE_GROW_BY_QUARTER(rmem2);
                bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
        }
	return 0;
}

char _license[] SEC("license") = "GPL";
