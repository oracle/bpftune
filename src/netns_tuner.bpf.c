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
#include "netns_tuner.h"

struct setup_net {
	struct net *net;
};

BPF_MAP_DEF(setup_net_map, BPF_MAP_TYPE_HASH, __u64, __u64, 65536, 0);

SEC("kprobe/setup_net")
int BPF_KPROBE(bpftune_setup_net, struct net *net)
{
	save_entry_data(setup_net_map, setup_net, net, net);
	return 0;
}

SEC("kretprobe/setup_net")
int BPF_KRETPROBE(bpftune_setup_net_return, int ret)
{
	struct bpftune_event event = {};
	struct net *netns;
	
	if (ret != 0)
		return 0;

	get_entry_data(setup_net_map, setup_net, net, netns);
	if (!netns)
		return 0;

	event.tuner_id = tuner_id;
	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.scenario_id = NETNS_SCENARIO_CREATE;
	event.netns_cookie = get_netns_cookie(netns);
	if (event.netns_cookie >= 0)
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);

	return 0;
}
