/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include "bpftune.bpf.h"

#ifdef BPFTUNE_LEGACY
/* legacy progs do not support BPF_CORE_READ(), so fall back to
 * tracing prog; we trace firing of cgroup prog instead.
 */
SEC("kprobe/__cgroup_bpf_run_filter_sysctl")
int BPF_KPROBE(trace_sysctl_write, struct ctl_table_header *head,
	       struct ctl_table *table, int write,
	       char **buf)
{
	struct bpftune_event event = {};
	struct ctl_dir *parent;	
	int current_pid = 0;
	struct ctl_table *tbl;
	const char *procname;

	if (!write)
		return 0;
	event.tuner_id = tuner_id;
	event.scenario_id = 0;
	current_pid = bpf_get_current_pid_tgid() >> 32;
	if (current_pid == bpftune_pid)
		return 0;
	parent = BPF_CORE_READ(head, parent);
	if (!parent)
		return 0;
	procname = BPF_CORE_READ(table, procname);
	if (!procname)
		return 0;
	if (bpf_probe_read(event.str, sizeof(event.str), procname) < 0)
		return 0;
	bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);	
	return 0;
}

/* dummy prog so we can use its firing as a means to collect info
 * via kprobe.
 */
SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
	return 1;
}

#else
/* should return 1 to allow read/write to proceed, 0 otherwise.
 * Currently just used to see if admin has fiddled with tunables
 * we're auto-tuning; if so, hands off for us...
 */
SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
	struct task_struct *current_task;
	struct bpftune_event event = {};
	int current_pid = 0, err;
	__u32 write = ctx->write;

	if (!write)
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
		bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	return 1;
}
#endif
