/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include <bpftune/bpftune.h>
#include "sysctl_tuner.skel.h"
#include "sysctl_tuner.skel.legacy.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

extern unsigned short learning_rate;

int init(struct bpftuner *tuner)
{
	bpftuner_bpf_init(sysctl, tuner, NULL);

	/* attach to root cgroup */
	if (bpftuner_cgroup_attach(tuner, "sysctl_write", BPF_CGROUP_SYSCTL))
		return 1;

	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_cgroup_detach(tuner, "sysctl_write", BPF_CGROUP_SYSCTL);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct bpftuner *t = NULL;

	bpftune_log(LOG_DEBUG, "sysctl write for '%s' (scenario %d) for tuner %s\n",
		    event->str, event->scenario_id, tuner->name);

	if (event->netns_cookie == (unsigned long)-1)
		return;

	bpftune_for_each_tuner(t) {
		struct bpftunable *tunable;

		bpftune_log(LOG_DEBUG, "checking tuner %s\n", tuner->name);
		bpftuner_for_each_tunable(t, tunable) {
			char path[512];

			bpftune_sysctl_name_to_path(tunable->desc.name, path,
						    sizeof(path));

			bpftune_log(LOG_DEBUG, "checking path %s against %s\n",
				    path, event->str);
			/* does name match last characters in path? want to
			 * avoid gc_thresh in routing table tuner matching
			 * gc_thresh3 in neigh table tuner for example.
			 */
			if (strstr(path, event->str)) {
				bpftune_log(LOG_ALERT,
					    "user modified sysctl '%s' that tuner '%s' uses; disabling '%s' for namespace cookie %ld\n",
					    event->str, t->name, t->name,
					    event->netns_cookie);
				bpftuner_netns_fini(t, event->netns_cookie, BPFTUNE_MANUAL);
				break;
			}
		}
	}
}
