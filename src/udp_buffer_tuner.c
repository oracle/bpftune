/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2025, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "udp_buffer_tuner.h"
#include "udp_buffer_tuner.skel.h"
#include "udp_buffer_tuner.skel.legacy.h"
#include "udp_buffer_tuner.skel.nobtf.h"

#include <bpftune/corr.h>

#include <unistd.h>
#include <linux/limits.h>

struct udp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ UDP_BUFFER_UDP_MEM,	BPFTUNABLE_SYSCTL, "net.ipv4.udp_mem",
	0, 3 },
{ UDP_BUFFER_NET_CORE_RMEM_MAX,	BPFTUNABLE_SYSCTL, "net.core.rmem_max",
	0, 1 },
{ UDP_BUFFER_NET_CORE_RMEM_DEFAULT, BPFTUNABLE_SYSCTL, "net.core.rmem_default",
	0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ UDP_BUFFER_INCREASE,	"need to increase UDP buffer size(s)",
	"Need to increase buffer size(s) to maximize throughput and reduce loss" },
{ UDP_BUFFER_DECREASE,	"need to decrease UDP buffer size(s)",
	"Need to decrease buffer size(s) to reduce memory utilization" },
{ UDP_MEM_PRESSURE,	"approaching UDP memory pressure",
	"Since memory pressure/exhaustion are unstable system states, adjust UDP memory-related tunables" },
{ UDP_MEM_EXHAUSTION,	"approaching UDP memory exhaustion",
	"Since memory exhaustion is a highly unstable state, adjust UDP memory-related tunables to avoid exhaustion" },
};

/* When UDP starts up, it calls nr_free_buffer_pages() and uses it to estimate
 * the values for udp_mem[0-2].  The equivalent of this estimate can be
 * retrieved via /proc/zoneinfo; in the Normal zone the number of managed
 * pages less the high watermark:
 *
 * Node 0, zone   Normal
 *   pages free     145661
 *         min      13560
 *         low      16950
 *         high     20340
 *         spanned  3282944
 *         present  3282944
 *         managed  3199514
 * 
 * In this case, we have 3199514 (managed) - 20340 (high watermark) = 3179174
 *
 * On startup udp_mem[0-2] are ~4.6%,  6.25%  and  9.37% of nr_free_buffer_pages.
 * Calculating these values for the above we get
 *
 * 127166 198698 297888
 *
 * ...versus initial values
 *
 * 185565 247423 371130
 *
 * Note that on < 4GB systems, zone Normals report 0 and zone DMA32 contains
 * the managed pages.
 */

int get_from_file(FILE *fp, const char *fmt, ...)
{
	char line[PATH_MAX];
	int ret = 0;
	va_list ap;

	va_start(ap, fmt);
	while (fgets(line, sizeof(line), fp)) {
		ret = vsscanf(line, fmt, ap);
		if (ret >= 1)
			break;
		else
			ret = -ENOENT;
	}
	va_end(ap);
	return ret;
}

long long nr_free_buffer_pages(bool initial)
{
	unsigned long nr_pages = 0;
	char *mzone = "Normal";
	FILE *fp;
	int err;

	err = bpftune_cap_add();
	if (err)
		return err;

retry:
	fp = fopen("/proc/zoneinfo", "r");

	if (!fp) {
		bpftune_log(LOG_DEBUG, "could not open /proc/zoneinfo: %s\n", strerror(errno));
	}
	while (fp && !feof(fp)) {
		long managed = 0, high = 0, free = 0, node;
		char zone[PATH_MAX] = "";

		if (get_from_file(fp, "Node %d, zone %s", &node, zone) < 0)
			break;
		if (strcmp(zone, mzone) != 0)
			continue;
		if (get_from_file(fp, " high\t%ld", &high) < 0)
			continue;	
		if (initial) {
			if (get_from_file(fp, " managed\t%ld", &managed) < 0)
				continue;
			if (managed > high)
				nr_pages += managed - high;
		} else {
			if (get_from_file(fp, " nr_free_pages\t%ld", &free))
				nr_pages += free;
		}
	}
	if (fp)
		fclose(fp);

	/* for < 4GB, managed pages are in DMA32 zone. */
	if (nr_pages == 0 && strcmp(mzone, "Normal") == 0) {
		mzone = "DMA32";
		goto retry;
	}

	bpftune_cap_drop();
	return nr_pages;
}

int init(struct bpftuner *tuner)
{
	/* on some platforms, this function is inlined */
	struct bpftunable *t;
	int pagesize;
	int err;

	if (tuner->bpf_support < BPFTUNE_SUPPORT_NORMAL)
		return -ENOTSUP;
	err = bpftuner_bpf_open(udp_buffer, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(udp_buffer, tuner, NULL);
	if (err)
		return err;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0)
		pagesize = 4096;
	bpftuner_bpf_var_set(udp_buffer, tuner, kernel_page_size, pagesize);
	bpftuner_bpf_var_set(udp_buffer, tuner, kernel_page_shift,
			     ilog2(pagesize));
	bpftuner_bpf_var_set(udp_buffer, tuner, sk_mem_quantum, SK_MEM_QUANTUM);
	bpftuner_bpf_var_set(udp_buffer, tuner, sk_mem_quantum_shift,
			     ilog2(SK_MEM_QUANTUM));
	bpftuner_bpf_var_set(udp_buffer, tuner, nr_free_buffer_pages,
			     nr_free_buffer_pages(true));
	bpftuner_bpf_sample_add(udp_buffer, tuner, udp_fail_rcv_sample);
	err = bpftuner_bpf_attach(udp_buffer, tuner);
	if (err)
		return err;
	err = bpftuner_tunables_init(tuner, UDP_BUFFER_NUM_TUNABLES, descs,
				     ARRAY_SIZE(scenarios), scenarios);
	if (err)
		return err;
	t = bpftuner_tunable(tuner, UDP_BUFFER_NET_CORE_RMEM_MAX);
	if (t)
		bpftuner_bpf_var_set(udp_buffer, tuner, rmem_max, t->current_values[0]);
	t = bpftuner_tunable(tuner, UDP_BUFFER_NET_CORE_RMEM_DEFAULT);
	if (t)
		bpftuner_bpf_var_set(udp_buffer, tuner, rmem_default, t->current_values[0]);

	return 0;
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

bool near_memory_exhaustion, under_memory_pressure, near_memory_pressure;


void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	const char *lowmem = "normal memory conditions";
	const char *reason = "unknown reason";
	__u64 udp_in, udp_drops, udp_drop_rate;
	int scenario = event->scenario_id;
	long in, in6, drops, drops6;
	const char *tunable;
	long new[3], old[3];
	int id;

	/* netns cookie not supported; ignore */
	if (event->netns_cookie == (unsigned long)-1)
		return;

	id = event->update[0].id;

	memcpy(new, event->update[0].new, sizeof(new));
	memcpy(old, event->update[0].old, sizeof(old));

	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for udp_buffer_tuner\n", id);
		return;
	}

	near_memory_exhaustion = bpftuner_bpf_var_get(udp_buffer, tuner,
						     near_memory_exhaustion);
	under_memory_pressure = bpftuner_bpf_var_get(udp_buffer, tuner,
					            under_memory_pressure);
	near_memory_pressure = bpftuner_bpf_var_get(udp_buffer, tuner,
						   near_memory_pressure);
	if (near_memory_exhaustion)
		lowmem = "near memory exhaustion";
	else if (under_memory_pressure)
		lowmem = "under memory pressure";
	else if (near_memory_pressure)
		lowmem = "near memory pressure";

	switch (id) {
	case UDP_BUFFER_UDP_MEM:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      event->netns_cookie, 3, new,
"Due to %s change %s(min pressure max) from (%ld %ld %ld) -> (%ld %ld %ld)\n",
					     lowmem, tunable, old[0], old[1], old[2],
					     new[0], new[1], new[2]);
		break;
	case UDP_BUFFER_NET_CORE_RMEM_MAX:
	case UDP_BUFFER_NET_CORE_RMEM_DEFAULT:
		bpftune_snmpstat_read(event->netns_cookie, AF_INET, "Udp:",
				      "InDatagrams", &in);
		bpftune_snmpstat_read(event->netns_cookie, AF_INET6, NULL,
				      "Udp6InDatagrams", &in6);
		bpftune_snmpstat_read(event->netns_cookie, AF_INET, "Udp:",
				      "RcvbufErrors", &drops);
		bpftune_snmpstat_read(event->netns_cookie, AF_INET6, NULL,
				      "Udp6RcvbufErrors", &drops6);
		udp_in = in + in6;
		udp_drops = drops + drops6;
		udp_drop_rate = (udp_drops * 1000)/udp_in;
		bpftune_log(BPFTUNE_LOG_LEVEL, "netns: %lu UDP in %lu, drops %lu drop rate %lu\n",
			    event->netns_cookie, udp_in, udp_drops, udp_drop_rate);
		switch (scenario) {
		case UDP_BUFFER_INCREASE:
			reason = "need to increase receive buffer size to maximize throughput";
			/* XXX add logic to spot unneeded increases */
			break;
		case UDP_BUFFER_DECREASE:
			reason = lowmem;
			break;
		}
		if (new[0] > UDP_BUFFER_MAX || new[0] < UDP_BUFFER_MIN)
			return;
		if (!bpftuner_tunable_sysctl_write(tuner, id, scenario,
						   event->netns_cookie, 1, new,
"Due to %s change %s from %ld -> %ld\n",
						   reason, tunable,
						   old[0], new[0])) {

			if (id == UDP_BUFFER_NET_CORE_RMEM_MAX)
				bpftuner_bpf_var_set(udp_buffer, tuner,
						     rmem_max, new[0]);
			else
				bpftuner_bpf_var_set(udp_buffer, tuner,
						     rmem_default, new[0]);

		}
		break;
	}
}
