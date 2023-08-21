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
#include "sample_tuner.skel.h"
#include "sample_tuner.skel.legacy.h"
#include "sample_tuner.skel.nobtf.h"

int init(struct bpftuner *tuner)
{
	return bpftuner_bpf_init(sample, tuner, NULL);
}

void fini(struct bpftuner *tuner)
{
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	bpftune_log(LOG_DEBUG, "event  (scenario %d) for tuner %s\n",
		    event->scenario_id, tuner->name);

}
