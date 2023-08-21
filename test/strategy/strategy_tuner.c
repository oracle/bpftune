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
#include "strategy_tuner.skel.h"
#include "strategy_tuner.skel.legacy.h"
#include "strategy_tuner.skel.nobtf.h"

static int evaluate_A(struct bpftuner *tuner, struct bpftuner_strategy *strategy)
{
	if (tuner->strategy == strategy)
		return 0;
	else
		return 1;
}

const char *progs_A[] = { "entry__proc_dostring_coredump", NULL };

struct bpftuner_strategy strategy_A = {
	.name		= "strategy_A",
	.description	= "first strategy",
	.evaluate	= evaluate_A,
	.timeout	= 30,
	.bpf_progs	= progs_A,
};

static int evaluate_B(struct bpftuner *tuner, struct bpftuner_strategy *strategy)
{
	if (tuner->strategy == strategy)
		return 0;
	else
		return 1;
}

const char *progs_B[] = { "entry__proc_dostring", NULL };

struct bpftuner_strategy strategy_B = {
        .name           = "strategy_B",
        .description    = "second strategy",
        .evaluate       = evaluate_B,
        .timeout        = 30,
        .bpf_progs      = progs_B,
};

struct bpftuner_strategy *strategies[] = { &strategy_A, &strategy_B, NULL };

int init(struct bpftuner *tuner)
{
	int err = bpftuner_strategies_add(tuner, strategies, &strategy_A);

	if (err)
		return err;
	return bpftuner_bpf_init(strategy, tuner, NULL);
}

void fini(struct bpftuner *tuner)
{
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	bpftune_log(LOG_DEBUG, "event  (scenario %d) for tuner %s, strategy %s\n",
		    event->scenario_id, tuner->name, tuner->strategy->name);
}
