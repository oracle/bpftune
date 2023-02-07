/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "tcp_buffer_tuner.h"

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

#define tcp_tunable_corr(__id, __cookie, __newval, __sk, __field_type, __field)\
	{								\
		__field_type __field;					\
		if (!bpf_probe_read_kernel(&__field, sizeof(__field),	\
				   (void *)__sk +			\
				   offsetof(struct tcp_sock, __field)))	\
                        corr_update_bpf(__id, __cookie, __newval,	\
					__field);			\
	}

static __always_inline bool tcp_nearly_out_of_memory(struct sock *sk,
						     struct bpftune_event *event)
{
	long limit_sk_mem_quantum[3] = { };
	long allocated;
	long mem[3] = { }, mem_new[3] = { };
	struct net *net = sk->sk_net.net;
	__u8 shift_left = 0, shift_right = 0;
	int i;

	if (!sk || !sk->sk_prot || !sk->sk_prot->memory_allocated)
		return false;
	allocated = sk->sk_prot->memory_allocated->counter;
	if (!allocated)
		return false;
	if (bpf_probe_read_kernel(mem,
				  sizeof(mem),
				  sk->sk_prot->sysctl_mem))
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
				 BPFTUNE_GROW_BY_QUARTER(mem[2]));
		/* if we still have room to grow mem exhaustion limit, do that,
		 * otherwise shrink wmem/rmem.
		 */
		if (mem_new[2] <= (nr_free_buffer_pages >> 2)) {
			send_sysctl_event(sk, TCP_MEM_EXHAUSTION,
					  TCP_BUFFER_TCP_MEM, mem, mem_new,
					  event);
			return true;
		}
		if (!net)
			return true;
		mem[0] = (long)(net->ipv4.sysctl_tcp_wmem[0]);
		mem[1] = (long)(net->ipv4.sysctl_tcp_wmem[1]);
		mem[2] = (long)(net->ipv4.sysctl_tcp_wmem[2]);
		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		mem_new[2] = BPFTUNE_SHRINK_BY_QUARTER(mem[2]);
		send_sysctl_event(sk, TCP_BUFFER_DECREASE,
				  TCP_BUFFER_TCP_WMEM,
				  mem, mem_new, event);
		if (!net)
			return true;
		mem[0] = (long)(net->ipv4.sysctl_tcp_rmem[0]);
		mem[1] = (long)(net->ipv4.sysctl_tcp_rmem[1]);
		mem[2] = (long)(net->ipv4.sysctl_tcp_rmem[2]);
		mem_new[0] = mem[0];
		mem_new[1] = mem[1];
		mem_new[2] = BPFTUNE_SHRINK_BY_QUARTER(mem[2]);
		send_sysctl_event(sk, TCP_BUFFER_DECREASE,
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
		bpftune_log("near/under pressure allocated %d/%d\n",
			     allocated, limit_sk_mem_quantum[1]);
		if (mem[0] < nr_free_buffer_pages >> 4)
			mem_new[0] = BPFTUNE_GROW_BY_QUARTER(mem[0]);
		bpftune_log("mem[1] %d limit %d\n", mem[1],
			      nr_free_buffer_pages >> 3);
		if (mem[1] < nr_free_buffer_pages >> 3)
			mem_new[1] = BPFTUNE_GROW_BY_QUARTER(mem[1]);
		mem_new[2] = min(nr_free_buffer_pages >> 2,
				 BPFTUNE_GROW_BY_QUARTER(mem[2]));
		send_sysctl_event(sk, TCP_MEM_PRESSURE,
				  TCP_BUFFER_TCP_MEM, mem, mem_new,
				  event);
		near_memory_pressure = true;
		return true;
	}
	near_memory_exhaustion = false;
	near_memory_pressure = false;

	return false;
}

SEC("fentry/tcp_enter_memory_pressure")
int BPF_PROG(bpftune_enter_memory_pressure, struct sock *sk)
{
	struct bpftune_event event = { 0 };

	(void) tcp_nearly_out_of_memory(sk, &event);
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
	struct bpftune_event event = { 0 };
	struct net *net = sk->sk_net.net;
	long wmem[3], wmem_new[3];
	long sndbuf;

	if (!sk || !net || tcp_nearly_out_of_memory(sk, &event))
		return 0;

	sndbuf = sk->sk_sndbuf;
	wmem[2] = net->ipv4.sysctl_tcp_wmem[2];

	if (NEARLY_FULL(sndbuf, wmem[2])) {

		if (tcp_nearly_out_of_memory(sk, &event))
			return 0;

		if (!net)
			return 0;
		wmem[0] = wmem_new[0] = net->ipv4.sysctl_tcp_wmem[0];
		wmem[1] = wmem_new[1] = net->ipv4.sysctl_tcp_wmem[1];
		wmem_new[2] = BPFTUNE_GROW_BY_QUARTER(wmem[2]);

		send_sysctl_event(sk, TCP_BUFFER_INCREASE,
				  TCP_BUFFER_TCP_WMEM,
				  wmem, wmem_new, &event);
		/* correlate changes to wmem with round-trip time to spot
		 * cases where buffer increase is correlated with longer
		 * latencies.
		 */
		tcp_tunable_corr(TCP_BUFFER_TCP_WMEM, event.netns_cookie,
				 wmem[2], sk, __u32, srtt_us);
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
	struct bpftune_event event = { 0 };
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
		send_sysctl_event(sk, TCP_BUFFER_INCREASE, TCP_BUFFER_TCP_RMEM,
				  rmem, rmem_new, &event);
		/* correlate changes to rmem with round-trip time to spot
		 * cases where buffer increase is correlated with longer
		 * latencies.
		 */
		tcp_tunable_corr(TCP_BUFFER_TCP_RMEM, event.netns_cookie,
				 rmem[2], sk, __u32, srtt_us);

	}
	return 0;
}

SEC("fentry/tcp_init_sock")
int BPF_PROG(bpftune_tcp_init_sock, struct sock *sk)
{
	struct bpftune_event event = { 0 };

	if (sk) {
		if (++tcp_sock_count > tcp_max_sock_count)
			tcp_max_sock_count = tcp_sock_count;
		(void) tcp_nearly_out_of_memory(sk, &event);
	}
	return 0;
}

SEC("fentry/tcp_release_cb")
int BPF_PROG(bpftune_tcp_release, struct sock *sk)
{
	if (tcp_sock_count > 0)
		tcp_sock_count--;
	return 0;
}

extern const void netdev_max_backlog __ksym;

#ifndef NET_RX_DROP
#define NET_RX_DROP	1
#endif

__u64 drop_count = 0;
__u64 drop_interval_start = 0;

SEC("fexit/enqueue_to_backlog")
int BPF_PROG(bpftune_enqueue_to_backlog, struct sk_buff *skb, int cpu,
	     unsigned int *qtail, int ret)
{
	struct bpftune_event event =  { 0 };
	long old[3], new[3];
	int max_backlog, *max_backlogp = (int *)&netdev_max_backlog;
	__u64 time;

	/* a high-frequency event so bail early if we can... */
	if (ret != NET_RX_DROP)
		return 0;

	/* if running out of memory, do not make a bad problem worse by
	 * increasing backlog queue size; better to drop traffic.
	 */
	if (under_memory_pressure || near_memory_exhaustion)
		return 0;

	drop_count++;

	if (bpf_probe_read_kernel(&max_backlog, sizeof(max_backlog),
				  max_backlogp))
		return 0;

	/* if we drop more than 1/4 of the backlog queue size/min,
	 * increase backlog queue size.  This means as the queue size
	 * increases, the likliehood of hitting that limit decreases.
	 */
	time = bpf_ktime_get_ns();
	if (!drop_interval_start || (time - drop_interval_start) > MINUTE) {
		drop_count = 1;
		drop_interval_start = time;
	}
	if (drop_count < (max_backlog >> 2))
		return 0;

	old[0] = max_backlog;
	new[0] = BPFTUNE_GROW_BY_QUARTER(max_backlog);
	send_sysctl_event(NULL, NETDEV_MAX_BACKLOG_INCREASE,
			  NETDEV_MAX_BACKLOG, old, new, &event);
	return 0;
}
