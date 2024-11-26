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
#include <bpftune/bpftune.h>
#include "sysctl_tuner.skel.h"
#include "sysctl_tuner.skel.legacy.h"
#include "sysctl_tuner.skel.nobtf.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>

extern unsigned short learning_rate;

int init(struct bpftuner *tuner)
{
	int err = bpftuner_bpf_init(sysctl, tuner, NULL);

	if (err)
		return err;
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

static const char *pid2cmd(int pid, char *cmd, size_t cmdsize)
{
	char cmdline[64];
	FILE *fp;

	snprintf(cmdline, sizeof(cmdline) - 1, "/proc/%d/cmdline", pid);
	fp = fopen(cmdline, "r");
	if (fp) {
		fgets(cmd, cmdsize - 1, fp);
		fclose(fp);
	}
	if (strlen(cmd) == 0)
		strncpy(cmd, "?", 2);
	return cmd;
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
			char path[PATH_MAX];

			bpftune_sysctl_name_to_path(tunable->desc.name, path,
						    sizeof(path));

			bpftune_log(LOG_DEBUG, "checking path %s against %s\n",
				    path, event->str);
			/* does name match last characters in path? want to
			 * avoid gc_thresh in routing table tuner matching
			 * gc_thresh3 in neigh table tuner for example.
			 */
			if (strstr(path, event->str)) {
				char cmd[1024] = {};

				bpftune_log(BPFTUNE_LOG_LEVEL,
					    "pid %ld, cmd '%s' modified sysctl '%s' that tuner '%s' uses; disabling '%s' for namespace cookie %ld\n",
					    event->pid,
					    pid2cmd(event->pid, cmd, sizeof(cmd)),
					    event->str, t->name, t->name,
					    event->netns_cookie);
				bpftuner_netns_fini(t, event->netns_cookie, BPFTUNE_MANUAL);
				break;
			}
		}
	}
}
