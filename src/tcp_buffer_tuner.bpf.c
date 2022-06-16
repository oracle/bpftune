/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "tcp_buffer_tuner.h"

bool under_memory_pressure = false;
bool near_memory_pressure = false;
bool near_memory_exhaustion = false;
int conn_count;

/* set from userspace */
int kernel_page_size;
int kernel_page_shift;
int sk_mem_quantum;
int sk_mem_quantum_shift;

static __always_inline void send_sysctl_event(struct sock *sk, int event_id,
					      long *old, long *new,
					      struct bpftune_event *event)
{
	struct net *net = sk->sk_net.net;

	event->tuner_id = tuner_id;
	event->netns_cookie = get_netns_cookie(net);
	event->update[0].id = event_id;
	event->update[0].old[0] = old[0];	
	event->update[0].old[1] = old[1];
	event->update[0].old[2] = old[2];
	event->update[0].new[0] = new[0];
	event->update[0].new[1] = new[1];
	event->update[0].new[2] = new[2];
	bpf_ringbuf_output(&ringbuf_map, event, sizeof(*event), 0);
}

static __always_inline bool tcp_nearly_out_of_memory(struct sock *sk,
						     struct bpftune_event *event)
{
	long allocated, limit_sk_mem_quantum[3] = { };
	struct net *net;

	if (!sk->sk_prot)
		return false;

	allocated = sk->sk_prot->memory_allocated->counter;
	if (bpf_probe_read(limit_sk_mem_quantum,
			   sizeof(limit_sk_mem_quantum),
			   sk->sk_prot->sysctl_mem))
		return false;

	if (!limit_sk_mem_quantum[2])
		return false;

	if (kernel_page_size > sk_mem_quantum)
		limit_sk_mem_quantum[2] <<= kernel_page_shift - sk_mem_quantum_shift;
	else if (kernel_page_size < sk_mem_quantum)
		limit_sk_mem_quantum[2] >>= sk_mem_quantum_shift - kernel_page_shift;

	if (NEARLY_FULL(allocated, limit_sk_mem_quantum[1])) {
		if (!near_memory_pressure) {


		}
		near_memory_pressure = true;
	}
	if (NEARLY_FULL(allocated, limit_sk_mem_quantum[2])) {
		if (!near_memory_exhaustion) {


		}
		near_memory_exhaustion = true;
	}

	return near_memory_pressure || near_memory_exhaustion;
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
	long wmem[3], wmem_new[3];
	long sndbuf;

	if (!sk || !net || near_memory_pressure || near_memory_exhaustion)
		return 0;

	sndbuf = sk->sk_sndbuf;
	wmem[2] = net->ipv4.sysctl_tcp_wmem[2];

	if (NEARLY_FULL(sndbuf, wmem[2])) {
		if (tcp_nearly_out_of_memory(sk, &event))
			return 0;

		wmem[0] = wmem_new[0] = net->ipv4.sysctl_tcp_wmem[0];
		wmem[1] = wmem_new[1] = net->ipv4.sysctl_tcp_wmem[1];
		wmem_new[2] = BPFTUNE_GROW_BY_QUARTER(wmem[2]);

		send_sysctl_event(sk, TCP_BUFFER_TCP_WMEM, wmem, wmem_new, &event);
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
	long rmem[3], rmem_new[3];
	long rcvbuf;

	if (!sk || !net)
		return 0;

	if ((sk->sk_userlocks & SOCK_RCVBUF_LOCK) || near_memory_pressure ||
	    near_memory_exhaustion)
		return 0;

	rcvbuf = sk->sk_rcvbuf;
	rmem[2] = net->ipv4.sysctl_tcp_rmem[2];

	if (NEARLY_FULL(rcvbuf, rmem[2])) {
		if (tcp_nearly_out_of_memory(sk, &event))
			return 0;

		rmem[0] = rmem_new[0] = net->ipv4.sysctl_tcp_rmem[0];
		rmem[1] = rmem_new[1] = net->ipv4.sysctl_tcp_rmem[1];
		rmem_new[2] = BPFTUNE_GROW_BY_QUARTER(rmem[2]);
		send_sysctl_event(sk, TCP_BUFFER_TCP_RMEM, rmem, rmem_new, &event);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
