/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <libbpftune.h>
#include "netns_tuner.h"
#include "netns_tuner.skel.h"

struct netns_tuner_bpf *skel;

#define NETNS	0

static struct bpftunable_desc descs[] = {
{
 NETNS, BPFTUNABLE_OTHER, "Network namespace", true, 0 },
};

static struct bpftunable_scenario scenarios[] = {
{ NETNS_SCENARIO_CREATE, "netns created", "network namespace creation" },
{ NETNS_SCENARIO_DESTROY, "netns destroyed", "network namespace destruction" },
};

int init(struct bpftuner *tuner)
{
	bpftuner_bpf_init(netns, tuner);

	return bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(__attribute__((unused))struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	unsigned long netns_cookie;
	int netns_fd = 0, ret;
	struct bpftuner *t;

	switch (event->scenario_id) {
	case NETNS_SCENARIO_CREATE:
		ret = bpftune_netns_info(event->pid, &netns_fd, &netns_cookie);
		if (ret || netns_cookie != event->netns_cookie) {
			
			bpftune_log(LOG_DEBUG, "netns cookie from pid %d %ld != %ld (cookie from event)\n",
				    event->pid, netns_cookie, event->netns_cookie);
			netns_fd = bpftune_netns_fd_from_cookie(event->netns_cookie);
			if (netns_fd < 0) {
				bpftune_log(LOG_DEBUG, "netns fd not found for cookie %ld: %s\n",
					    event->netns_cookie, strerror(-netns_fd));
				return;
			}
		}
		bpftune_log(LOG_DEBUG, "got netns fd %d for cookie %ld\n",
			    netns_fd, event->netns_cookie);
		bpftune_for_each_tuner(t)
			bpftuner_netns_init(t, event->netns_cookie);
		close(netns_fd);
		break;
	case NETNS_SCENARIO_DESTROY:
		bpftune_for_each_tuner(t)
			bpftuner_netns_fini(t, event->netns_cookie);
		break;

	}
	bpftuner_tunable_update(tuner, NETNS, event->scenario_id, netns_fd,
				"netns %s (cookie %ld)\n",
				event->scenario_id == NETNS_SCENARIO_CREATE ?
				"created" : "destroyed",
				event->netns_cookie);
}
