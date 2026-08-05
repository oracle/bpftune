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
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <bpftune/bpftune.h>

enum tcp_cong_tunables {
	TCP_CONG,
	TCP_ALLOWED_CONG,
	TCP_AVAILABLE_CONG,
	TCP_CONG_DEFAULT,
	TCP_THIN_LINEAR_TIMEOUTS
};

enum tcp_cong_scenarios {
	TCP_CONG_SET,
};

#define CONG_MAXNAME	16

#define CONN_TUNER_BPF	"bpftune_conn_tuner"

enum tcp_states {
	TCP_STATE_CONG_CUBIC,
	TCP_STATE_CONG_BBR,
	TCP_STATE_CONG_HTCP,
	TCP_STATE_CONG_DCTCP,
	NUM_TCP_CONG_ALGS
};

/* match order of enum tcp_states */
const char congs[NUM_TCP_CONG_ALGS][6] = {
	{ 'c', 'u', 'b', 'i', 'c', '\0' },
	{ 'b', 'b', 'r', '\0' },
	{ 'h', 't', 'c', 'p', '\0' },
	{ 'd', 'c', 't', 'c', 'p', '\0' }
};

struct tcp_conn_metric {
	__u64 state_flags;	/* logical OR of states */
	__u64 greedy_count;	/* amount of times greedy option was taken */
	__u64 min_rtt;
	__u64 max_rate_delivered;
	__u64 metric_count;
	__u64 metric_value;
};

#define NUM_TCP_CONN_METRICS	NUM_TCP_CONG_ALGS

struct tcp_conn_event_data {
	struct in6_addr raddr;
	__u64 state_flags;
	__u64 rate_delivered;
	__u64 min_rtt;
	__u64 metric;
};

struct remote_host {
	__u64 min_rtt;
	__u64 max_rate_delivered;
	__u64 instances;
	struct tcp_conn_metric metrics[NUM_TCP_CONN_METRICS];
};

/* collect per-conn data once we see > REMOTE_HOST_MIN_INSTANCES */
#define REMOTE_HOST_MIN_INSTANCES	4

/* if total retrans/segs_out > 1(2^DROP_SHIFT) (1/64 by default)
 * apply BBR congestion control.
 */
#define DROP_SHIFT	6

#define RTT_SCALE       1000000
#define DELIVERY_SCALE  1000000

/* The metric we calculate compares current connection min_rtt and rate_delivered to
 * the min rtt and max rate delivered we have observed for the remote host.
 * The idea is that we want to reward congestion control algorithms that minimize
 * RTT and maximize delivery rate, as these are operating at the bottleneck
 * bandwitdh, which is the optimal operating mode.  This does not unduly favour
 * a particular algorithm in practice it seems, and choices can fluctuate over
 * time.  One concern is that the delivery rate is rather low and does not
 * fluctuate much - we see 1 most often for delivery rate.  Our cost function
 * rates rtt deviation and delivery rate deviation equally however; this may
 * need to be tweaked.
 *
 * Cost function is
 *
 * (conn_min_rtt - min_rtt)        +  (max_delivery_rate - delivery_rate)
 *  -----------------------           -----------------------------------
 *  overall min rtt                    overall_max_delivery_rate
 *
 *
 * Both of these are scaled by RTT_SCALE, DELIVERY_SCALE to ensure we get integer
 * values.  Note we do not need to square values because both are asymmetric;
 * a connection min_rtt > overall_min_rtt is bad, while a delivery_rate < overall
 * max delivery rate is bad.  As a result a higher cost here is a problem, and
 * we pick action (congestion algorithm) with minimum cost.
 *
 * Metrics are updated using standard reinforcement learning update;
 *
 * new_estimate = old_estimate + learning_rate * (reward - old_estimate)
 */
static __always_inline __u64 tcp_metric_calc(struct remote_host *r,
					     __u64 min_rtt,
					     __u64 rate_delivered)
{
	__u64 metric = 0;

	if (!r->min_rtt || min_rtt < r->min_rtt)
		r->min_rtt = min_rtt;
	if (!r->max_rate_delivered || rate_delivered > r->max_rate_delivered)
		r->max_rate_delivered = rate_delivered;
	if (r->min_rtt)
		metric += ((min_rtt - r->min_rtt)*RTT_SCALE)/r->min_rtt;
	if (r->max_rate_delivered)
		metric +=
		    ((r->max_rate_delivered - rate_delivered)*DELIVERY_SCALE)/r->max_rate_delivered;
	return metric;
}
