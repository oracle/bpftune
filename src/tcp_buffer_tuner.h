/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/bpftune.h>

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM          4096
#endif

enum tcp_buffer_tunables {
	TCP_BUFFER_TCP_WMEM,
	TCP_BUFFER_TCP_RMEM,
	TCP_BUFFER_TCP_MEM,
	TCP_BUFFER_TCP_MAX_ORPHANS,
	TCP_BUFFER_NUM_TUNABLES,
};

enum tcp_buffer_scenarios {
	TCP_BUFFER_INCREASE,
	TCP_BUFFER_DECREASE,
	TCP_BUFFER_NOCHANGE_LATENCY,
	TCP_MEM_PRESSURE,
	TCP_MEM_EXHAUSTION,
	TCP_MAX_ORPHANS_INCREASE,
};
