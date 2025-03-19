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

#define UDP_BUFFER_MIN		8192
#define UDP_BUFFER_MAX		268435456		/* 256Mb */

#ifndef SK_MEM_QUANTUM
#define SK_MEM_QUANTUM          4096
#endif

enum udp_buffer_tunables {
	UDP_BUFFER_UDP_MEM,
	UDP_BUFFER_NET_CORE_RMEM_MAX,
	UDP_BUFFER_NET_CORE_RMEM_DEFAULT,
	UDP_BUFFER_NUM_TUNABLES
};

enum tcp_buffer_scenarios {
	UDP_BUFFER_INCREASE,
	UDP_BUFFER_DECREASE,
	UDP_MEM_PRESSURE,
	UDP_MEM_EXHAUSTION,
};
