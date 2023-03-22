/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

#include "cong_tuner.h"

#define CONG_MAXNAME	16

struct remote_host {
	__u64 last_retransmit;
	__u64 retransmits;
	bool retransmit_threshold;
	char cong_alg[CONG_MAXNAME];
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

	if (remote_host->last_retransmit &&
	    (now - remote_host->last_retransmit) > HOUR) {
		remote_host->retransmits = 0;
		remote_host->retransmit_threshold = false;
	}
	remote_host->last_retransmit = now;

	return remote_host->retransmit_threshold;
}

static __always_inline int get_sk_key(struct sock *sk, struct in6_addr *key)
{
	int family = BPF_CORE_READ(sk, sk_family);
	switch (family) {
	case AF_INET:
		return bpf_probe_read_kernel(key, sizeof(sk->sk_daddr),
					     __builtin_preserve_access_index(&sk->sk_daddr));
		
	case AF_INET6:
		return bpf_probe_read_kernel(key, sizeof(*key),
					     __builtin_preserve_access_index(&sk->sk_v6_daddr));
	default:
		return -EINVAL;
	}
}

static __always_inline struct remote_host *get_remote_host(struct in6_addr *key)
{
	struct remote_host *remote_host = NULL;

	remote_host = bpf_map_lookup_elem(&remote_host_map, key);
        if (!remote_host) {
		struct remote_host new_remote_host = {};

		bpf_map_update_elem(&remote_host_map, key, &new_remote_host,
				    BPF_ANY);
		remote_host = bpf_map_lookup_elem(&remote_host_map, key);
        }
	return remote_host;
}

#ifdef BPFTUNE_LEGACY
/* in legacy mode, use sockops prog to set cong algoritm when retransmit
 * threshold is passed.  Because we need to enable retransmit sock ops
 * events on socket accept/connect, this does not work for existing
 * connections which were initiated prior to bpftune starting.
 */
SEC("sockops")
int bpf_sockops(struct bpf_sock_ops *ops)
{
	struct remote_host *remote_host;
	struct sockaddr_in6 sin6 = {};
	struct in6_addr *key = &sin6.sin6_addr;
	char buf[CONG_MAXNAME] = {};
	int ret;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* enable retransmission events */
		bpf_sock_ops_cb_flags_set(ops, BPF_SOCK_OPS_RETRANS_CB_FLAG);
		return 1;
	case BPF_SOCK_OPS_RETRANS_CB:
		break;
	default:
		return 1;
	}
	sin6.sin6_family = ops->family;
	sin6.sin6_addr.s6_addr32[0] = ops->remote_ip6[0];
	sin6.sin6_addr.s6_addr32[1] = ops->remote_ip6[1];
	sin6.sin6_addr.s6_addr32[2] = ops->remote_ip6[2];
	sin6.sin6_addr.s6_addr32[3] = ops->remote_ip6[3];

	remote_host = get_remote_host(key);
	if (!remote_host)
		return 1;
	if (!remote_host->retransmit_threshold)
		return 1;

	/* desired cong alg not yet set... */
	if (remote_host->cong_alg[0] == '\0')
		return 1;
	/* check if cong alg already set */
	if (bpf_getsockopt(ops, SOL_TCP, TCP_CONGESTION, &buf, sizeof(buf)))
		return 1;
	if (__strncmp(remote_host->cong_alg, buf, sizeof(buf)) == 0)
		return 1;
	ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION,
			     &remote_host->cong_alg, sizeof(remote_host->cong_alg));
	bpftune_debug("set cong '%s': %d\n", remote_host->cong_alg, ret);
	return 1;
}

/* count retransmits here per remote addr here... */
SEC("raw_tracepoint/tcp_retransmit_skb")
#else
SEC("tp_btf/tcp_retransmit_skb")
#endif
int BPF_PROG(cong_retransmit, struct sock *sk, struct sk_buff *skb)
{
	struct remote_host *remote_host;
	struct bpftune_event event = {};
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event.raw_data;
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct in6_addr *key = &sin6->sin6_addr;
	__u32 segs_out = 0, total_retrans = 0;
	const char bbr[CONG_MAXNAME] = "bbr";
	int id = TCP_CONG_BBR;
	struct net *net;

	if (get_sk_key(sk, key))
		return 0;

	remote_host = get_remote_host(key);
	if (!remote_host)
		return 0;

	remote_host->retransmits++;

	/* already sent ringbuf message */
	if (remote_host_retransmit_threshold(remote_host))
		return 0;

	if (bpf_probe_read_kernel(&segs_out, sizeof(segs_out),
				  __builtin_preserve_access_index(&tp->segs_out)) ||
	    bpf_probe_read_kernel(&total_retrans, sizeof(total_retrans),
				  __builtin_preserve_access_index(&tp->total_retrans)))
		return 0;

	/* with a retransmission rate of > 1%, BBR performs much better. */
	if (total_retrans > (segs_out >> 5)) {
		remote_host->retransmit_threshold = true;
		__builtin_memcpy(remote_host->cong_alg, bbr,
			 sizeof(remote_host->cong_alg));
	} else {
		return 0;
	}

	sin6->sin6_family = BPF_CORE_READ(sk, sk_family);
	event.tuner_id = tuner_id;
	event.scenario_id = id;
	net = BPF_CORE_READ(sk, sk_net.net);
	event.netns_cookie = get_netns_cookie(net);
	if (event.netns_cookie < 0)
		return 0;
	bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);

	return 0;
}

#ifndef BPFTUNE_LEGACY
/* specify congestion control algorithm here via iterator (to catch
 * existing + new TCP connections) for connections to remote hosts which
 * have seen retransmits in the past.  The event sent from the retransmit
 * threshold being surpassed will trigger the iterator.
 */
SEC("iter/tcp")
int bpftune_cong_iter(struct bpf_iter__tcp *ctx)
{
	struct sock_common *skc = ctx->sk_common;
	struct remote_host *remote_host;
	char buf[CONG_MAXNAME] = {};
	struct in6_addr key = {};
	struct tcp_sock *tp;
        struct sock *sk = NULL;
	int ret;

	if (skc) {
		tp = bpf_skc_to_tcp_sock(skc);
		sk = (struct sock *)tp;
	}	
	if (!tp || !sk)
		return 0;

	if (get_sk_key(sk, &key))
		return 0;

	remote_host = get_remote_host(&key);
	if (!remote_host)
		return 0;

	if (!remote_host->retransmit_threshold ||
	    remote_host->cong_alg[0] == '\0')
		return 0;

	/* check if cong alg already set */
	if (bpf_getsockopt(tp, SOL_TCP, TCP_CONGESTION, &buf, sizeof(buf)) ||
	    __strncmp(remote_host->cong_alg, buf, sizeof(buf)) == 0)
		return 0;

	ret = bpf_setsockopt(tp, SOL_TCP, TCP_CONGESTION,
			     &remote_host->cong_alg, sizeof(remote_host->cong_alg));
	bpftune_debug("set cong '%s': %d\n", remote_host->cong_alg, ret);
	return 0;
}
#endif
