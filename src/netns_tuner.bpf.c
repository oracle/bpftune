/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "netns_tuner.h"


extern const void init_net __ksym;

SEC("fexit/setup_net")
int BPF_PROG(bpftune_setup_net, struct net *net, struct user_namespace *user_ns,
	     int ret)
{
	struct bpftune_event event = {};

	if (ret != 0 || net == NULL || net == &init_net)
		return 0;

	event.tuner_id = tuner_id;
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.scenario_id = NETNS_SCENARIO_CREATE;
	event.netns_cookie = net->net_cookie;
	bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);

	return 0;
}

SEC("fentry/net_free")
int BPF_PROG(bpftune_net_free, struct net *net)
{
	struct bpftune_event event = {};

	if (!net)
		return 0;

	event.tuner_id = tuner_id;
	event.scenario_id = NETNS_SCENARIO_DESTROY;
	event.netns_cookie = net->net_cookie;
	bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
