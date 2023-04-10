/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/bpftune.h>

enum tcp_cong_tunables {
	TCP_CONG,
};

enum tcp_cong_scenarios {
	TCP_CONG_BBR,
	TCP_CONG_HTCP,
};

/* a long fat pipe is defined as having a BDP of > 10^5; it implies latency
 * plus high bandwith.  In such cases use htcp.
 */
#define BDP_LFP		100000
