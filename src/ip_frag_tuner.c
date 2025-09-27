/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include <bpftune/corr.h>

#include "ip_frag_tuner.h"
#include "ip_frag_tuner.skel.h"
#include "ip_frag_tuner.skel.legacy.h"
#include "ip_frag_tuner.skel.nobtf.h"

#include <unistd.h>
#include <linux/limits.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ IP_FRAG_MAX_THRESHOLD, BPFTUNABLE_SYSCTL, "net.ipv4.ipfrag_high_thresh",
	0, 1 },
{ IP6_FRAG_MAX_THRESHOLD, BPFTUNABLE_SYSCTL, "net.ipv6.ip6frag_high_thresh",
	BPFTUNABLE_OPTIONAL, 1 },
};

static struct bpftunable_scenario scenarios[] = {
	BPFTUNABLE_SCENARIO(IP_FRAG_THRESHOLD_INCREASE,
			"need to increase IP fragmentation high threshold",
	"this allows additional memory to be used to accommodate more defragmentation."),
	BPFTUNABLE_SCENARIO(IP_FRAG_THRESHOLD_DECREASE,
			"need to decrease IP fragmentation high threshold",
	"as we increased fragmentation high threshold we saw a correlation in reassembly failures; this indicates that we received more invalid fragments as we added memory to process them.  As such, further increases are likely to be ineffective so reduce high threshold."),
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
	long new, old, reasmfails, reasmreqds, reasm_failrate;
	int scenario = event->scenario_id;
	struct corr c = { 0 };
	long double corr = 0;
	struct corr_key key;
	const char *tunable;
	int id, af;

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
	key.id = (__u64)id;
	key.netns_cookie = event->netns_cookie;

	af = id == IP_FRAG_MAX_THRESHOLD ? AF_INET : AF_INET6;
	if (!bpftune_snmpstat_read(event->netns_cookie, af, NULL,
				   "ReasmFails", &reasmfails) &&
	    !bpftune_snmpstat_read(event->netns_cookie, af, NULL,
				   "ReasmReqds", &reasmreqds)) {
		/* % of reasm fails */
		reasm_failrate = (reasmfails * 100)/reasmreqds;
		bpftune_log(LOG_DEBUG, "got %ld reasmfails, %ld reasmreqds, %ld reasm fail rate (% of reasm failures)\n",
			    reasmfails, reasmreqds, reasm_failrate);
		if (corr_update_user(tuner->corr_map_fd, key.id, key.netns_cookie,
				     (__u64)new, (__u64)reasm_failrate)) {
			bpftune_log(LOG_DEBUG, "corr map fd %d xxx update failed %d\n", tuner->corr_map_fd, errno);
		}
	}
	if (!bpf_map_lookup_elem(tuner->corr_map_fd, &key, &c)) {
		corr = corr_compute(&c);
		bpftune_log(LOG_DEBUG, "covar for '%s' netns %ld (new %ld): %LF ; corr %LF\n",
			    tunable, key.netns_cookie, new, covar_compute(&c), corr);
		if (corr > CORR_THRESHOLD && scenario == IP_FRAG_THRESHOLD_INCREASE) {
			scenario = IP_FRAG_THRESHOLD_DECREASE;
			new = BPFTUNE_SHRINK_BY_DELTA(old);
		}
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
