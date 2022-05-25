/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(trace_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb)
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
int bpf_sockops(struct bpf_sock_ops *ops)
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
