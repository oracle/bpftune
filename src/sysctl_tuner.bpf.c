/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#include "vmlinux.h"

#include "bpftune.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 512);
	__type(key, int);
	__type(value, int);
} perf_map SEC(".maps");

unsigned int tuner_id;
unsigned int bpftune_pid;

/* should return 1 to allow read/write to proceed, 0 otherwise.
 * Currently just used to see if admin has fiddled with tunables
 * we're auto-tuning; if so, hands off for us...
 */
SEC("cgroup/sysctl")
int sysctl_write(struct bpf_sysctl *ctx)
{
	struct bpftune_event event = {};
	int err;

	if (!ctx->write)
		return 1;
	event.tuner_id = tuner_id;
	event.scenario_id = 0;
	err = bpf_sysctl_get_name(ctx, event.str, sizeof(event.str), 0);
	if (err <= 0 || err > BPFTUNE_MAX_NAME)
		return 1;

	bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU,	
			      &event, sizeof(event));
	return 1;
}

char _license[] SEC("license") = "GPL";
