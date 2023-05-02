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

#include <bpftune/bpftune.bpf.h>

/* fire when coredump sysctls are read */
BPF_FENTRY(proc_dostring_coredump, struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	struct bpftune_event event = {};
	int ret, scenario_id = 0;

	/* tuner id is a global declared in bpftune.bpf.h and set by bfttune
	 * when the tuner is added.
	 */
	event.tuner_id = tuner_id;
	event.scenario_id = scenario_id;
	ret = bpf_ringbuf_output(&ring_buffer_map, &event, sizeof(event), 0);
	bpftune_debug("tuner [%d] scenario [%d]: event send: %d ",
		      tuner_id, scenario_id, ret);
	return 0;
}
