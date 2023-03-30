/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/bpftune.bpf.h>

/* use kprobe here as it is not in fastpath and the function has a large
 * number of args not well handled by fentry.  We trace the sysctl set
 * because we cannot derive the net namespace easily from sysctl progs.
 */
SEC("kprobe/__cgroup_bpf_run_filter_sysctl")
int BPF_KPROBE(bpftune_sysctl, struct ctl_table_header *head,
	       struct ctl_table *table, int write, char **buf)
{
	/* these are used to get offsets of fields within structures to
 	 * get pointer to struct net from the struct ctl_table * we
 	 * are passed.
 	 */
	struct ctl_table_set *dummy_ctl_table_set = NULL;
	struct net *dummy_net = NULL;

	struct bpftune_event event = {};
	struct ctl_dir *root, *parent, *gparent, *ggparent;
	struct ctl_dir *gggparent;
	int current_pid = 0;
	struct ctl_table *tbl;
	const char *procname;
	void *net;

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
	gparent = BPF_CORE_READ(parent, header.parent);
	if (!gparent)
		return 0;
	ggparent = BPF_CORE_READ(gparent, header.parent);
	if (!ggparent) {
		root = gparent;
	} else {
		gggparent = BPF_CORE_READ(ggparent, header.parent);
		if (!gggparent) {
			root = ggparent;
		} else {
			root = BPF_CORE_READ(gggparent, header.parent);
			if (!root)
				root = gggparent;
		}
	}
	net = (void *)root -
		(__u64)__builtin_preserve_access_index(&dummy_net->sysctls) -
		(__u64)__builtin_preserve_access_index(&dummy_ctl_table_set->dir);
	event.netns_cookie = get_netns_cookie(net);
	if (event.netns_cookie == (unsigned long)-1)
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
