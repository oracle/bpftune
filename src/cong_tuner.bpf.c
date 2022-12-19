/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

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
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	struct in6_addr *key = &sin6->sin6_addr;
	__u32 segs_out = 0, total_retrans = 0;
	const char bbr[CONG_MAXNAME] = "bbr";
	const char htcp[CONG_MAXNAME] = "htcp";
	int id = TCP_CONG_BBR;
	__u64 bdp = 0;

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
	 * below translates to ~ 3.125%.  With a high bandwidth delay
	 * product (BDP), use h-tcp.
	 */
	if (total_retrans > (segs_out >> 5)) {
		__u32 rate_delivered, rate_interval_us;
		__u32 mss_cache, srtt_us;
		__u64 bdp;

		remote_host->retransmit_threshold = true;
		remote_host->last_retransmit = bpf_ktime_get_ns();
		if (!bpf_probe_read_kernel(&rate_delivered, sizeof(rate_delivered),
					 (void *)sk + offsetof(struct tcp_sock, rate_delivered)) &&
		    !bpf_probe_read_kernel(&rate_interval_us, sizeof(rate_interval_us),
					   (void *)sk + offsetof(struct tcp_sock, rate_interval_us)) &&
		    !bpf_probe_read_kernel(&mss_cache, sizeof(mss_cache),
					   (void *)sk + offsetof(struct tcp_sock, mss_cache)) &&
		    !bpf_probe_read_kernel(&srtt_us, sizeof(srtt_us),
					   (void *)sk + offsetof(struct tcp_sock, srtt_us))) {
			srtt_us  = srtt_us >> 3;
			bpftune_log("rate_delivered %d, rate_interval_us %d\n",
				    rate_delivered, rate_interval_us);
			bpftune_log("srtt %d mss_cache %d\n",
				    srtt_us, mss_cache);
			bdp = rate_interval_us > 0 ?
			      (__u64)(rate_delivered * mss_cache * srtt_us)/rate_interval_us :
				     0;
			bpftune_log("bdp estimate: %ld: LFP: %d\n",
				    bdp, BDP_LFP);
		}
		/* a long fat pipe is defined as having a BDP of > 10^5;
		 * it implies latency plus high bandwith.  In such cases,
		 * use htcp.  Note we multiply the usual LFP metric (10^5)
		 * by 5 to be conservative.
		 */

		if (bdp > BDP_LFP * 5) {
			__builtin_memcpy(remote_host->cong_alg, htcp,
					 sizeof(remote_host->cong_alg));
			id = TCP_CONG_HTCP;
		} else {
			__builtin_memcpy(remote_host->cong_alg, bbr,
				 sizeof(remote_host->cong_alg));
		}
	} else {
		return 0;
	}

	sin6->sin6_family = sk->sk_family;
	event.tuner_id = tuner_id;
	event.scenario_id = id;
	event.netns_cookie = get_netns_cookie(sk->sk_net.net);
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
		       &remote_host->cong_alg, sizeof(remote_host->cong_alg));

	return 0;
}
