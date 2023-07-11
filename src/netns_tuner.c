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

#include <bpftune/libbpftune.h>
#include "netns_tuner.h"
#include "netns_tuner.skel.h"
#include "netns_tuner.skel.legacy.h"

struct netns_tuner_bpf *skel;

#define NETNS	0

static struct bpftunable_desc descs[] = {
{
 NETNS, BPFTUNABLE_OTHER, "Network namespace", BPFTUNABLE_NAMESPACED, 0 },
};

static struct bpftunable_scenario scenarios[] = {
{ NETNS_SCENARIO_CREATE, "netns created", "network namespace creation" },
{ NETNS_SCENARIO_DESTROY, "netns destroyed", "network namespace destruction" },
};

int init(struct bpftuner *tuner)
{
	const char *optionals[] = { "entry__net_free", NULL };
	int err;

	if (!bpftune_netns_cookie_supported())
		return -ENOTSUP;

	err = bpftuner_bpf_open(netns, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(netns, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_attach(netns, tuner, optionals);
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
			netns_fd = bpftuner_netns_fd_from_cookie(tuner, event->netns_cookie);
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
			bpftuner_netns_fini(t, event->netns_cookie, BPFTUNE_GONE);
		break;
	default:
		return;
	}
	bpftuner_tunable_update(tuner, NETNS, event->scenario_id, netns_fd,
				"netns %s (cookie %ld)\n",
				event->scenario_id == NETNS_SCENARIO_CREATE ?
				"created" : "destroyed",
				event->netns_cookie);
}
