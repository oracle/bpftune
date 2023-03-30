/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

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
