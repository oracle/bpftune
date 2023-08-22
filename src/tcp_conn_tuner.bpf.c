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

#include "tcp_conn_tuner.h"

const char bbr[4] = { 'b', 'b', 'r', '\0' };

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


static __always_inline bool
retransmit_threshold(struct remote_host *remote_host,
		     u32 segs_out, u32 total_retrans)
{
	__u64 now;

	if (!remote_host)
		return false;

	remote_host->retransmits++;

	now = bpf_ktime_get_ns();

	/* If last time we surpassed the retransmit threshold is greater than
	 * an hour, reset.
	 */
	if (remote_host->last_retransmit &&
	    (now - remote_host->last_retransmit) > HOUR) {
		remote_host->retransmits = 0;
		remote_host->retransmit_threshold = false;
	} else if (total_retrans > (segs_out >> 5)) {
		/* with retransmission rate of > 1%, BBR performs better. */
		remote_host->retransmit_threshold = true;
		__builtin_memcpy(remote_host->cong_alg, bbr,
				 sizeof(remote_host->cong_alg));
	}
	remote_host->last_retransmit = now;

	return remote_host->retransmit_threshold;
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

static __always_inline void set_cong(void *ctx, struct remote_host *remote_host)
{
	char buf[CONG_MAXNAME] = {};
	int ret;

	/* check if cong alg already set */
	if (bpf_getsockopt(ctx, SOL_TCP, TCP_CONGESTION, &buf, sizeof(buf)) ||
	    __strncmp(remote_host->cong_alg, buf, sizeof(buf)) == 0)
		return;
	ret = bpf_setsockopt(ctx, SOL_TCP, TCP_CONGESTION,
			     &remote_host->cong_alg,
			     sizeof(remote_host->cong_alg));
	bpftune_debug("cong_tuner: set cong '%s': %d\n",
		      remote_host->cong_alg, ret);
}

#ifdef BPFTUNE_LEGACY
/* in legacy mode, use sockops prog to set cong algoritm when retransmit
 * threshold is passed.  Because we need to enable retransmit sock ops
 * events on socket accept/connect, this does not work for existing
 * connections which were initiated prior to bpftune starting.
 */
SEC("sockops")
int cong_tuner_sockops(struct bpf_sock_ops *ops)
{
	struct remote_host *remote_host;
	struct bpftune_event event = {};
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event.raw_data;
	struct in6_addr *key = &sin6->sin6_addr;
	bool prior_retransmit_threshold;

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
	sin6->sin6_family = ops->family;
	switch (ops->family) {
	case AF_INET:
		sin6->sin6_addr.s6_addr32[0] = ops->remote_ip4;
		break;
	case AF_INET6:
		sin6->sin6_addr.s6_addr32[0] = ops->remote_ip6[0];
		sin6->sin6_addr.s6_addr32[1] = ops->remote_ip6[1];
		sin6->sin6_addr.s6_addr32[2] = ops->remote_ip6[2];
		sin6->sin6_addr.s6_addr32[3] = ops->remote_ip6[3];
		break;
	default:
		return 1;
	}

	remote_host = get_remote_host(key);
	if (!remote_host)
		return 1;
	prior_retransmit_threshold = remote_host->retransmit_threshold;

	if (!retransmit_threshold(remote_host, ops->segs_out,
				  ops->total_retrans))
		return 1;

	set_cong(ops, remote_host);

	/* if first sock to cross threshold for remote host, send event. */
	if (!prior_retransmit_threshold) {
		event.tuner_id = tuner_id;
		event.scenario_id = TCP_CONG_BBR;
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	}

	return 1;
}
#else
static __always_inline int get_sk_key(struct sock *sk, struct in6_addr *key)
{
	int family = BPFTUNE_CORE_READ(sk, sk_family);

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

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(cong_retransmit, struct sock *sk, struct sk_buff *skb)
{
	struct remote_host *remote_host;
	struct bpftune_event event = {};
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&event.raw_data;
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct in6_addr *key = &sin6->sin6_addr;
	__u32 segs_out = 0, total_retrans = 0;
	int id = TCP_CONG_BBR;
	struct net *net;

	if (get_sk_key(sk, key))
		return 0;

	remote_host = get_remote_host(key);
	if (!remote_host)
		return 0;

	/* already sent ringbuf message */
	if (remote_host->retransmit_threshold)
		return 0;

	segs_out = BPFTUNE_CORE_READ(tp, segs_out);
	total_retrans = BPFTUNE_CORE_READ(tp, total_retrans);

	if (!retransmit_threshold(remote_host, segs_out, total_retrans))
                return 0;

	sin6->sin6_family = BPFTUNE_CORE_READ(sk, sk_family);
	event.tuner_id = tuner_id;
	event.scenario_id = id;
	net = BPFTUNE_CORE_READ(sk, sk_net.net);
	event.netns_cookie = get_netns_cookie(net);
	if (event.netns_cookie < 0)
		return 0;
	bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);

	return 0;
}


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
	struct in6_addr key = {};
        struct sock *sk = NULL;

	if (skc)
		sk = (struct sock *)bpf_skc_to_tcp_sock(skc);
	if (!sk)
		return 0;

	if (get_sk_key(sk, &key))
		return 0;

	remote_host = get_remote_host(&key);
	if (!remote_host)
		return 0;

	if (!remote_host->retransmit_threshold ||
	    remote_host->cong_alg[0] == '\0')
		return 0;

	set_cong(sk, remote_host);

	return 0;
}
#endif
