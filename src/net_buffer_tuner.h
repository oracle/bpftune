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

enum net_buffer_tunables {
	NETDEV_MAX_BACKLOG,
	FLOW_LIMIT_CPU_BITMAP,
	NETDEV_BUDGET,
	NETDEV_BUDGET_USECS,
	HIGH_ORDER_ALLOC_DISABLE,
	NET_BUFFER_NUM_TUNABLES,
};

enum net_buffer_scenarios {
	NETDEV_MAX_BACKLOG_INCREASE,	
	FLOW_LIMIT_CPU_SET,
	NETDEV_BUDGET_INCREASE,
	NETDEV_BUDGET_DECREASE,
	HIGH_ORDER_ALLOC_ENABLE,
};

/* above 50msec is too high */
#define NETDEV_BUDGET_USECS_MAX	(1000 * 50)
