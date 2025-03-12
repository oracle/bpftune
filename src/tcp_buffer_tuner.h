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

#include <bpftune/bpftune.h>

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM          4096
#endif

enum tcp_buffer_tunables {
	TCP_BUFFER_TCP_WMEM,
	TCP_BUFFER_TCP_RMEM,
	TCP_BUFFER_TCP_MEM,
	TCP_BUFFER_TCP_MODERATE_RCVBUF,
	TCP_BUFFER_TCP_NO_METRICS_SAVE,
	TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE,
	TCP_BUFFER_NET_CORE_HIGH_ORDER_ALLOC_DISABLE,
	TCP_BUFFER_TCP_SYNCOOKIES,
	TCP_BUFFER_TCP_MAX_SYN_BACKLOG,
	TCP_BUFFER_TCP_MAX_ORPHANS,
	TCP_BUFFER_NUM_TUNABLES,
};

enum tcp_buffer_scenarios {
	TCP_BUFFER_INCREASE,
	TCP_BUFFER_DECREASE,
	TCP_BUFFER_DECREASE_LATENCY,
	TCP_MEM_PRESSURE,
	TCP_MEM_EXHAUSTION,
	TCP_MODERATE_RCVBUF_ENABLE,
	TCP_LOW_MEM_ENTER_ENABLE,
	TCP_LOW_MEM_LEAVE_DISABLE,
	TCP_MAX_SYN_BACKLOG_INCREASE,
	TCP_MAX_SYN_BACKLOG_DECREASE,
	TCP_SYNCOOKIES_ENABLE,
	TCP_SYNCOOKIES_DISABLE,
	TCP_MAX_ORPHANS_INCREASE,
};

#define TCP_RESET_COUNT			100

#define TCP_SYN_BACKLOG_MIN		128

#define TCP_SYNCOOKIES_BAD_COUNT	1024
