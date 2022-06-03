/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2022, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"
#include "tcp_buffer_tuner.h"


/* By instrumenting tcp_sndbuf_expand() we know the following, due to the
 * fact tcp_should_expand_sndbuf() has returned true:
 *
 * - the socket is not locked (SOCK_SNDBUF_LOCKED);
 * - we are not under global TCP memory pressure; and
 * - not under soft global TCP memory pressure; and
 * - we have not filled the congestion window.
 *
 * However, all that said, we may soon run out of sndbuf space, so
 * if it is nearly exhausted (>75% full), expand by 25%.
 */
SEC("fentry/tcp_sndbuf_expand")
int BPF_PROG(bpftune_sndbuf_expand, struct sock *sk)
{
	struct bpftune_event event = {};
	struct net *net = sk->sk_net.net;
	int sndbuf, wmem2;

	if (!sk || !net)
		return 0;

	sndbuf = sk->sk_sndbuf;
	wmem2 = net->ipv4.sysctl_tcp_wmem[2];

	if (NEARLY_FULL(sndbuf, wmem2)) {
		long wmem0 = net->ipv4.sysctl_tcp_wmem[0];
		long wmem1 = net->ipv4.sysctl_tcp_wmem[1];

		event.tuner_id = tuner_id;
		event.netns_cookie = get_netns_cookie(net);
		event.update[0].id = TCP_BUFFER_TCP_WMEM;
		event.update[0].old[0] = wmem0;
		event.update[0].new[0] = wmem0;
		event.update[0].old[1] = wmem1;
		event.update[0].new[1] = wmem1;
		event.update[0].old[2] = wmem2;
		event.update[0].new[2] = BPFTUNE_GROW_BY_QUARTER(wmem2);
		bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
