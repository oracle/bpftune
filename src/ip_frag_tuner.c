/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "ip_frag_tuner.h"
#include "ip_frag_tuner.skel.h"
#include "ip_frag_tuner.skel.legacy.h"
#include "ip_frag_tuner.skel.nobtf.h"

#include <unistd.h>
#include <linux/limits.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ IP_FRAG_MAX_THRESHOLD, BPFTUNABLE_SYSCTL, "net.ipv4.ipfrag_high_thresh",
	BPFTUNABLE_NAMESPACED, 1 },
{ IP6_FRAG_MAX_THRESHOLD, BPFTUNABLE_SYSCTL, "net.ipv6.ip6frag_high_thresh",
	BPFTUNABLE_NAMESPACED | BPFTUNABLE_OPTIONAL, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ IP_FRAG_THRESHOLD_INCREASE,	"need to increase IP fragmentation high threshold",
  "this allows additional memory to be used to accommodate more defragmentation." },
};

int init(struct bpftuner *tuner)
{
	int err;

	err = bpftuner_bpf_init(ip_frag, tuner, NULL);
	if (err)
		return err;
	return bpftuner_tunables_init(tuner, IP_FRAG_NUM_TUNABLES, descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	int scenario = event->scenario_id;
	const char *tunable;
	long new, old;
	int id;

	/* netns cookie not supported; ignore */
	if (event->netns_cookie == (unsigned long)-1)
		return;

	id = event->update[0].id;

	memcpy(&new, event->update[0].new, sizeof(new));
	memcpy(&old, event->update[0].old, sizeof(old));

	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for ip_frag_tuner\n", id);
		return;
	}
	switch (id) {
	case IP_FRAG_MAX_THRESHOLD:
	case IP6_FRAG_MAX_THRESHOLD:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      event->netns_cookie, 1, &new,
"Due to approaching fragmentation maximum threshold change %s from (%ld) -> (%ld)\n",
					     tunable, old, new);
		break;
	default:
		break;
	}
}
