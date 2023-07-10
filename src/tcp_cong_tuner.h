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

enum tcp_cong_tunables {
	TCP_CONG,
};

enum tcp_cong_scenarios {
	TCP_CONG_BBR,
	TCP_CONG_HTCP,
};

#define CONG_MAXNAME	16

/* a long fat pipe is defined as having a BDP of > 10^5; it implies latency
 * plus high bandwith.  In such cases use htcp.
 */
#define BDP_LFP		100000
