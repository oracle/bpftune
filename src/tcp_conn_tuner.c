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

#include <bpftune/libbpftune.h>

#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tcp_conn_tuner.h"
#include "tcp_conn_tuner.skel.h"
#include "tcp_conn_tuner.skel.legacy.h"
#include "tcp_conn_tuner.skel.nobtf.h"

static struct bpftunable_desc descs[] = {
 
{ TCP_CONG, BPFTUNABLE_OTHER, "TCP congestion control", 0, 0 },
{ TCP_THIN_LINEAR_TIMEOUTS, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_thin_linear_timeouts", BPFTUNABLE_NAMESPACED, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ TCP_CONG_SET,		"specify TCP congestion control algorithm",
  "To optimize TCP performance, a TCP congestion control algorithm was chosen to mimimize round-trip time and maximize delivery rate." },
};

struct tcp_conn_tuner_bpf *skel;

int tcp_iter_fd;

int init(struct bpftuner *tuner)
{
	struct bpftunable *t;
	int i, err;

	/* make sure cong modules are loaded; might be builtin so do not
 	 * shout about errors.
 	 */
	for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {
		char name[32];

		snprintf(name, sizeof(name), "net/ipv4/tcp_%s.ko", congs[i]);
		err = bpftune_module_load(name);
		if (err != -EEXIST)
			bpftune_log(LOG_DEBUG, "could not load module '%s': %s\n",
				    name, strerror(-err));
	}

	err = bpftuner_bpf_init(tcp_conn, tuner, NULL);
	if (err)
		return err;

	err = bpftune_cap_add();
	if (err) {
		bpftune_log(LOG_ERR, "cannot add caps: %s\n", strerror(-err));
		return 1;
	}

	/* attach to root cgroup */
	err = bpftuner_cgroup_attach(tuner, "conn_tuner_sockops", BPF_CGROUP_SOCK_OPS);
	if (err)
		goto out;

	err = bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				     ARRAY_SIZE(scenarios), scenarios);
	if (err)
		goto out;
	t = bpftuner_tunable(tuner, TCP_THIN_LINEAR_TIMEOUTS);
	if (t)
		bpftuner_bpf_var_set(tcp_conn, tuner, tcp_thin_lto, t->initial_values[0]);
out:
	bpftune_cap_drop();
	return err;
}

void summarize(struct bpftuner *tuner)
{
	struct bpf_map *map = bpftuner_bpf_map_get(tcp_conn, tuner, remote_host_map);
	struct in6_addr key, *prev_key = NULL;
	int map_fd = bpf_map__fd(map);
	unsigned long greedy_count = 0;
	__u64 thin_lto_choices;
	__u64 *cong_choices;
	int i;

	thin_lto_choices = bpftuner_bpf_var_get(tcp_conn, tuner, tcp_thin_lto_choices);
	if (thin_lto_choices) {
		bpftune_log(BPFTUNE_LOG_LEVEL, "# Summary: tcp_conn_tuner: set 'net.ipv4.tcp_thin_linear_timeouts' for %lu connections to improve responsiveness of thin flows durning retransmission\n",
			    thin_lto_choices);
	}
	cong_choices = bpftuner_bpf_var_get(tcp_conn, tuner, tcp_cong_choices);
	if (cong_choices) {
		bpftune_log(BPFTUNE_LOG_LEVEL,
			    "# Summary: tcp_conn_tuner: %20s %20s\n",
			    "CongAlg", "Count");
		for (i = 0; i < NUM_TCP_CONG_ALGS; i++) {
			bpftune_log(BPFTUNE_LOG_LEVEL,
				    "# Summary: tcp_conn_tuner: %20s %20lu\n",
				    congs[i], cong_choices[i]);
		}
	}
	while (!bpf_map_get_next_key(map_fd, prev_key, &key)) {
		char buf[INET6_ADDRSTRLEN];
		struct remote_host r;

		prev_key = &key;

		if (bpf_map_lookup_elem(map_fd, &key, &r))
			continue;

		bpftune_log(LOG_DEBUG, "# Summary: tcp_conn_tuner: %48s %8s %20s %8s %8s %8s %8s\n",
			    "IPAddress", "CongAlg", "Metric", "Count", "Greedy", "MinRtt", "MaxDlvr");
		inet_ntop(AF_INET6, &key, buf, sizeof(buf));

		for (i = 0; i < NUM_TCP_CONN_METRICS; i++) {

			bpftune_log(LOG_DEBUG, "# Summary: tcp_conn_tuner: %48s %8s %20llu %8llu %8llu %8llu %8llu\n",
				    buf, congs[i],
				    r.metrics[i].metric_value,
				    r.metrics[i].metric_count,
				    r.metrics[i].greedy_count,
				    r.metrics[i].min_rtt,
				    r.metrics[i].max_rate_delivered);
			bpftuner_tunable_stats_update(tuner, TCP_CONG,
						      TCP_CONG_SET, true,
						      r.metrics[i].metric_count);
			greedy_count += r.metrics[i].greedy_count;
		}
	}
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_cgroup_detach(tuner, "conn_tuner_sockops", BPF_CGROUP_SOCK_OPS);
	summarize(tuner);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct tcp_conn_event_data *event_data = (struct tcp_conn_event_data *)&event->raw_data;
	__u8 state = event_data->state_flags & 0x3;
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &event_data->raddr, buf, sizeof(buf));

	bpftune_log(LOG_DEBUG,
"%s: %s: cong alg '%s': got rate_delivered %lld, rtt %lld, metric %lld\n",
				tuner->name,
				buf, congs[state],
				event_data->rate_delivered,
				event_data->min_rtt,
				event_data->metric);
}
