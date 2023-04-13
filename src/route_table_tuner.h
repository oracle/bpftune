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

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

enum route_table_tunables {
	ROUTE_TABLE_IPV6_MAX_SIZE,
	ROUTE_TABLE_NUM_TUNABLES
};

enum route_table_scenarios {
	ROUTE_TABLE_FULL,
};

struct tbl_stats {
	int family;
	int entries;
	int gc_entries;
	int max;
	int ifindex;
	char dev[IFNAMSIZ];
};
