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

__u64 tcp_cong_choices[NUM_TCP_CONG_ALGS];

BPF_MAP_DEF(remote_host_map, BPF_MAP_TYPE_HASH, struct in6_addr, struct remote_host, 1024, 0);

BPF_MAP_DEF(sk_storage_map, BPF_MAP_TYPE_SK_STORAGE, int, __u64, 0, BPF_F_NO_PREALLOC);

/* if we have not looked up the host >= REMOTE_HOST_MIN_INSTANCES, return NULL. 
 * This ensures we only apply RL to hosts with which we have multiple
 * interactions.
 */
static __always_inline struct remote_host *get_remote_host(struct in6_addr *key,
							   bool initial)
{
	struct remote_host *remote_host = NULL;

	remote_host = bpf_map_lookup_elem(&remote_host_map, key);
	if (!remote_host) {
		struct remote_host new_remote_host = { .instances = 1};

		bpf_map_update_elem(&remote_host_map, key, &new_remote_host,
				    BPF_ANY);
		return NULL;
	}
	/* bump for initial conn established */
	if (initial)
		remote_host->instances++;
	if (remote_host->instances < REMOTE_HOST_MIN_INSTANCES)
		return NULL;
	return remote_host;
}

static __always_inline void set_cong(struct bpf_sock_ops *ops, __u8 i)
{
	int ret;

	ret = bpf_setsockopt(ops, SOL_TCP, TCP_CONGESTION, (void *)congs[i],
			     sizeof(congs[i]));
	tcp_cong_choices[i & (NUM_TCP_CONG_ALGS - 1)]++;
	/* update state */
	if (!ret) {
		struct bpf_sock *sk = ops->sk;
		__u64 *statep;

		if (!sk)
			return;
		statep = bpf_sk_storage_get(&sk_storage_map, sk, 0,
                                            BPF_SK_STORAGE_GET_F_CREATE);
                if (statep)
			*statep = (__u64)i;
	}
}

SEC("sockops")
int conn_tuner_sockops(struct bpf_sock_ops *ops)
{
	int cb_flags = BPF_SOCK_OPS_STATE_CB_FLAG|BPF_SOCK_OPS_RETRANS_CB_FLAG;
	struct remote_host *remote_host;
	struct bpftune_event event = {};
	struct tcp_conn_event_data *event_data = (struct tcp_conn_event_data *)&event.raw_data;
	struct in6_addr *key = &event_data->raddr;
	struct bpf_sock *sk = ops->sk;
	__u64 *statep = NULL;
	bool initial = false;
	int state;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* enable other needed events */
		bpf_sock_ops_cb_flags_set(ops, cb_flags);
		initial = true;
		break;
	case BPF_SOCK_OPS_RETRANS_CB:
		/* set individual cong algorithm to BBR if retransmit rate
		 * is > 1/(2^DROP_SHIFT) of packets out.
		 */
		if (ops->total_retrans > (ops->segs_out >> DROP_SHIFT)) {
			if (sk) {
				statep = bpf_sk_storage_get(&sk_storage_map, sk,
							    0, 0);
			}
			if (!statep || *statep != TCP_STATE_CONG_BBR) {
				set_cong(ops, TCP_STATE_CONG_BBR);
				/* no more need for retrans events... */
				bpf_sock_ops_cb_flags_set(ops, BPF_SOCK_OPS_STATE_CB_FLAG);
			}
		}
		return 1;
	case BPF_SOCK_OPS_STATE_CB:
		state = ops->args[1];
		switch (state) {
		case BPF_TCP_FIN_WAIT1:
		case BPF_TCP_CLOSE_WAIT:
			if (!sk)
				return 1;
			break;
		default:
			return 1;
		}
		break;
	default:
		return 1;
	}
	switch (ops->family) {
	case AF_INET:
		key->s6_addr32[2] = bpf_htonl(0xffff);
		key->s6_addr32[3] = ops->remote_ip4;
		break;
	case AF_INET6:
		key->s6_addr32[0] = ops->remote_ip6[0];
		key->s6_addr32[1] = ops->remote_ip6[1];
		key->s6_addr32[2] = ops->remote_ip6[2];
		key->s6_addr32[3] = ops->remote_ip6[3];
		break;
	default:
		return 1;
	}
	remote_host = get_remote_host(key, initial);
	/* no RL unless seen a number of times... */
	if (!remote_host)
		return 1;

	switch (ops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
		__u64 metric_value = 0, metric_min = ~((__u64)0x0);
		__u8 i, ncands = 0, minindex = 0, s;
		__u8 cands[NUM_TCP_CONN_METRICS];

		/* find best (minimum) metric and use cong alg based on it. */
		for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
			cands[i] = 0;
			metric_value = remote_host->metrics[i].metric_value;
			if (metric_value > metric_min)
				continue;
			else if (metric_value < metric_min) {
				cands[0] = i;
				ncands = 1;
			} else if (metric_value == metric_min) {
				cands[ncands] = i;
				ncands++;
			}
			metric_min = metric_value;
		}
		/* if multiple min values, choose randomly. */
		if (ncands > 1 && ncands <= NUM_TCP_CONN_METRICS) {
			__u32 choice = bpf_get_prandom_u32() % ncands;

			/* verifier complains about variable stack offset */
			switch (choice) {
			case 0:
				minindex = cands[0]; break;
			case 1:
				minindex = cands[1]; break;
			case 2:
				minindex = cands[2]; break;
			case 3:
				minindex = cands[3]; break;
			default:
				return 1;
			}
		} else if (ncands == 1) {
			minindex = cands[0];
		} else {
			return 1;
		}
		minindex &= (NUM_TCP_CONN_METRICS - 1);
		/* choose random alg 5% of the time (1/20) */
		s = epsilon_greedy(minindex, NUM_TCP_CONN_METRICS, 20);
		s &= 0x3;

		set_cong(ops, s);

		return 1;
	}
	case BPF_SOCK_OPS_STATE_CB: {
		/* update metric/send metric event on connection close. */
		__u64 metric, metric_old, min_rtt, rate_interval_us, rate_delivered, mss;
		struct tcp_conn_metric *m;
		struct tcp_sock *tp;
		bool greedy = true;
		__u8 i, s;

		if (!sk)
			return 1;
		if (!remote_host)
			return 1;
		/* retrieve state indicating which cong alg was set */
		statep = bpf_sk_storage_get(&sk_storage_map, sk, 0, 0);
		if (!statep)
			return 1;
		s = *statep & 0x3;
		tp = bpf_skc_to_tcp_sock(sk);
		if (!tp)
			return 1;
		min_rtt = (__u64)tp->rtt_min.s[0].v;
		rate_interval_us = (__u64)tp->rate_interval_us;
		rate_delivered = (__u64)tp->rate_delivered;
		mss = (__u64)tp->mss_cache;
		rate_delivered = rate_interval_us ?
			(__u64)(rate_delivered * mss)/rate_interval_us : 0;

		m = &remote_host->metrics[s];
		if (!m->min_rtt || min_rtt < m->min_rtt)
                	m->min_rtt = min_rtt;
                if (!m->max_rate_delivered || rate_delivered > m->max_rate_delivered)
                	m->max_rate_delivered = rate_delivered;

		metric = tcp_metric_calc(remote_host, min_rtt, m->max_rate_delivered);
		event_data->state_flags = *statep;
		event_data->min_rtt = min_rtt;
		event_data->rate_delivered = rate_delivered;
		event_data->metric = metric;

		for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
			if (s == i)
				continue;
			if (remote_host->metrics[i].metric_value < m->metric_value) {
				greedy = false;
				break;
			}
		}
		metric_old = m->metric_value;
		m->metric_value = rl_update(metric_old, metric, BPFTUNE_BITSHIFT);
		m->metric_count++;
		if (greedy)
			m->greedy_count++;
		if (debug) {
			event.tuner_id = tuner_id;
			bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
		}
		return 1;
	}
	default:
		return 1;
	}
	return 1;
}
