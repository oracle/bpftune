/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

unsigned int bpftune_pid;

/* should return 1 to allow read/write to proceed, 0 otherwise.
 * Currently just used to see if admin has fiddled with tunables
 * we're auto-tuning; if so, hands off for us...
 */
SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
	struct task_struct *current_task;
	struct bpftune_event event = {};
	int current_pid, err;

	if (!ctx->write)
		return 1;
	event.tuner_id = tuner_id;
	event.scenario_id = 0;
	err = bpf_sysctl_get_name(ctx, event.str, sizeof(event.str), 0);
	if (err <= 0 || err > BPFTUNE_MAX_NAME)
		return 1;
	/* bpf_get_current_pid_tgid() helper not allowed for sysctl */
	current_task = (struct task_struct *)bpf_get_current_task();
	current_pid = BPF_CORE_READ(current_task, pid);
	if (current_pid != bpftune_pid)
		bpf_ringbuf_output(&ringbuf_map, &event, sizeof(event), 0);
	return 1;
}
