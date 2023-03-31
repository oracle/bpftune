/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include <time.h>
#include "route_table_tuner.h"
#include "route_table_tuner.skel.h"
#include "route_table_tuner.skel.legacy.h"

struct route_table_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ ROUTE_TABLE_IPV6_MAX_SIZE,		BPFTUNABLE_SYSCTL,
		"net.ipv6.route.max_size",		true, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ ROUTE_TABLE_FULL,	"destination table nearly full",
		"destination table is nearly full, preventing new entries from being added." },
};

int init(struct bpftuner *tuner)
{
	bpftuner_bpf_open(route_table, tuner);
	bpftuner_bpf_load(route_table, tuner);
	bpftuner_bpf_attach(route_table, tuner, NULL);
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
	long new[3], old[3];
	int id;

	switch (event->scenario_id) {
	case ROUTE_TABLE_FULL:
		id = event->update[0].id;
		memcpy(new, event->update[0].new, sizeof(new));
		memcpy(old, event->update[0].old, sizeof(old));
		
		bpftuner_tunable_sysctl_write(tuner, id, ROUTE_TABLE_FULL,
					      event->netns_cookie, 1, new,
"Due to dst table filling up, change net.ipv6.route.max_size from %d -> %d\n",
					      old[0], new[0]);
		break;
	default:
		return;
	}
}
