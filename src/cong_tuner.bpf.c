/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

struct remote_host {
	__u64 last_retransmit;
	__u64 retransmits;
	bool retransmit_threshold;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct in6_addr);
	__type(value, struct remote_host);
} remote_host_map SEC(".maps");


/* If last time we surpassed the retransmit threshold is greater than an hour,
 * reset.
 */
static __always_inline bool
remote_host_retransmit_threshold(struct remote_host *remote_host)
{
	__u64 now;

	if (!remote_host)
		return false;

	now = bpf_ktime_get_ns();

	if (now - remote_host->last_retransmit > HOUR) {
		remote_host->retransmits = 0;
		remote_host->retransmit_threshold = false;
	}

	return remote_host->retransmit_threshold;
}

static __always_inline int get_sk_key(struct sock *sk, struct in6_addr *key)
{
	switch (sk->sk_family) {
	case AF_INET:
		return bpf_probe_read_kernel(key, sizeof(sk->sk_daddr),
					     &sk->sk_daddr);
		
	case AF_INET6:
		return bpf_probe_read_kernel(key, sizeof(*key),
					     &sk->sk_v6_daddr);
	default:
		return -EINVAL;
	}
}

static __always_inline struct remote_host *get_remote_host(struct sock *sk,
							   struct in6_addr *key)
{
	struct remote_host *remote_host = NULL;

	if (get_sk_key(sk, key))
		return NULL;

	remote_host = bpf_map_lookup_elem(&remote_host_map, key);
        if (!remote_host) {
		struct remote_host new_remote_host = {};

		bpf_map_update_elem(&remote_host_map, key, &new_remote_host,
				    BPF_ANY);
		remote_host = bpf_map_lookup_elem(&remote_host_map, key);
        }
	return remote_host;
}

/* count retransmits here per remote addr here... */
SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(cong_retransmit, struct sock *sk, struct sk_buff *skb)
{
	struct remote_host *remote_host;
	struct bpftune_event event = {};
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event.raw_data;
	struct in6_addr *key = &sin6->sin6_addr;
	__u32 segs_out = 0, total_retrans = 0;

	remote_host = get_remote_host(sk, key);
	if (!remote_host)
		return 0;

	remote_host->retransmits++;

	if (remote_host->retransmit_threshold)
		return 0;

	if (bpf_probe_read_kernel(&segs_out, sizeof(segs_out),
				  (void *)sk + offsetof(struct tcp_sock, segs_out)) ||
	    bpf_probe_read_kernel(&total_retrans, sizeof(total_retrans),
				  (void *)sk + offsetof(struct tcp_sock, total_retrans)))
		return 0;

	/* with a retransmission rate of > 1%, BBR performs much better;
	 * below translates to ~ 3.125%.
	 */
	if (total_retrans > (segs_out >> 5)) {
		remote_host->retransmit_threshold = true;
		remote_host->last_retransmit = bpf_ktime_get_ns();
		__bpf_printk("exceeded retrans threshold with %u/%u\n",
			     total_retrans, segs_out);
	} else {
		return 0;
	}

	sin6->sin6_family = sk->sk_family;
	event.tuner_id = tuner_id;
	event.scenario_id = 0;
	event.netns_cookie = get_netns_cookie(sk->sk_net.net);
	bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);

	return 0;
}

/* specify BBR congestion control algorithm here via iterator (to catch
 * existing + new TCP connections) for connections to remote hosts which
 * have seen retransmits in the past.  The event sent from the retransmit
 * threshold being surpassed will trigger the iterator.
 */
SEC("iter/tcp")
int bpftune_cong_iter(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	char bbr[TCP_CA_NAME_MAX] = "bbr";
	struct remote_host *remote_host;
	struct in6_addr key = {};
	struct tcp_sock *tp;
        struct sock *sk = NULL;

	if (skc) {
		tp = bpf_skc_to_tcp_sock(skc);
		sk = (struct sock *)tp;
	}	
	if (!tp || !sk)
		return 0;

	remote_host = get_remote_host(sk, &key);
	if (!remote_host)
		return 0;

	if (!remote_host_retransmit_threshold(remote_host))
		return 0;
		
	bpf_setsockopt(tp, SOL_TCP, TCP_CONGESTION,
		       &bbr, sizeof(bbr));

	return 0;
}
