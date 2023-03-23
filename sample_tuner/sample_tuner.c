/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <libbpftune.h>
#include <bpftune.h>
#include "sample_tuner.skel.h"
#include "sample_tuner.skel.legacy.h"

int init(struct bpftuner *tuner)
{
	bpftuner_bpf_init(sample, tuner, NULL);
	return 0;
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
