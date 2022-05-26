/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

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
		key_raddr[3] = ops->remote_ip6[3];
		key_raddr[1] = ops->remote_ip6[1];
		key_raddr[0] = ops->remote_ip6[0];
		key_raddr[2] = ops->remote_ip6[2];
		break;
	case AF_INET:
		key_raddr[0] = ops->remote_ip4;
		break;
	default:
		return -EINVAL;
	}

        return 0;
}

#define RETRANSMIT_THRESH       100

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

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(cong_retransmit, struct sock *sk, struct sk_buff *skb)
{
	struct in6_addr key = {};
	struct remote_host *remote_host;
	int ret;

	__bpf_printk("got retransmit!!!\n");

	switch (sk->sk_family) {
	case AF_INET:
		ret = bpf_probe_read(&key, sizeof(sk->sk_daddr),
				     &sk->sk_daddr);
		break;
	case AF_INET6:
		ret = bpf_probe_read(&key, sizeof(key),
				     &sk->sk_v6_daddr);
		break;
	default:
		return 0;
	}
	if (ret < 0)
		return 0;
	remote_host = bpf_map_lookup_elem(&remote_host_map, &key);
	if (remote_host)
		remote_host_retransmit(remote_host);
	return 0;
}

SEC("sockops")
int cong_sockops(struct bpf_sock_ops *ops)
{
	struct bpftune_event event = {};
	char bbr[TCP_CA_NAME_MAX] = "bbr";
	struct remote_host *remote_host;
	struct in6_addr key;
	void *ctx;
	int ret = 0;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (!tcpbpf_set_key(ops, &key))
			return 0;
		break;
	default:
		return 0;
	}

	remote_host = bpf_map_lookup_elem(&remote_host_map, &key);
	if (!remote_host)
		return 0;

	/* We have retransmitted to this host, so use BBR as congestion algorithm */
	if (remote_host_retransmit_threshold(remote_host)) {
		ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION,
				     &bbr, sizeof(bbr));
		event.tuner_id = tuner_id;
		event.scenario_id = 0;
		__bpf_printk("bpf sockops (srtt_us %d), cong bbr result %d\n",
			     ops->srtt_us, ret);
		bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
	}
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
