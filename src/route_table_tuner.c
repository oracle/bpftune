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

#include <bpftune/libbpftune.h>
#include <time.h>
#include "route_table_tuner.h"
#include "route_table_tuner.skel.h"
#include "route_table_tuner.skel.legacy.h"
#include "route_table_tuner.skel.nobtf.h"

struct route_table_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ ROUTE_TABLE_IPV6_MAX_SIZE,		BPFTUNABLE_SYSCTL,
		"net.ipv6.route.max_size",
		BPFTUNABLE_NAMESPACED | BPFTUNABLE_OPTIONAL, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ ROUTE_TABLE_FULL,	"destination table nearly full",
		"destination table is nearly full, preventing new entries from being added." },
};

int init(struct bpftuner *tuner)
{
	const char *optionals[] = { "entry__fib6_age", NULL };

	int err = bpftuner_bpf_init(route_table, tuner, optionals);

	if (err)
		return err;
	return bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	int id;

	switch (event->scenario_id) {
	case ROUTE_TABLE_FULL:
		id = event->update[0].id;
	
		bpftuner_tunable_sysctl_write(tuner, id, ROUTE_TABLE_FULL,
					      event->netns_cookie, 1,
					      event->update[0].new,
"Due to dst table filling up, change net.ipv6.route.max_size from %ld -> %ld\n",
					      event->update[0].old[0],
					      event->update[0].new[0]);
		break;
	default:
		return;
	}
}
