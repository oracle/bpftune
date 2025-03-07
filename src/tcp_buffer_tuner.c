/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2023, Oracle and/or its affiliates. */

#include <bpftune/libbpftune.h>
#include "tcp_buffer_tuner.h"
#include "tcp_buffer_tuner.skel.h"
#include "tcp_buffer_tuner.skel.legacy.h"
#include "tcp_buffer_tuner.skel.nobtf.h"

#include <bpftune/corr.h>

#include <unistd.h>
#include <linux/limits.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ TCP_BUFFER_TCP_WMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_wmem",
	BPFTUNABLE_NAMESPACED, 3 },
{ TCP_BUFFER_TCP_RMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_rmem",
	BPFTUNABLE_NAMESPACED, 3 },
{ TCP_BUFFER_TCP_MEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_mem",
	0, 3 },
{ TCP_BUFFER_TCP_MODERATE_RCVBUF, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_moderate_rcvbuf",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_NO_METRICS_SAVE, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_no_metrics_save",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_no_ssthresh_metrics_save",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_MAX_ORPHANS, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_max_orphans",
	0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ TCP_BUFFER_INCREASE,	"need to increase TCP buffer size(s)",
	"Need to increase buffer size(s) to maximize throughput" },
{ TCP_BUFFER_DECREASE,	"need to decrease TCP buffer size(s)",
	"Need to decrease buffer size(s) to reduce memory utilization" },
{ TCP_BUFFER_DECREASE_LATENCY,
			"need to decrease TCP buffer size due to latency",
	"Latency is starting to correlate with buffer size increases, so decrease buffer size to avoid this effect" },
{ TCP_MEM_PRESSURE,	"approaching TCP memory pressure",
	"Since memory pressure/exhaustion are unstable system states, adjust tcp memory-related tunables" },
{ TCP_MEM_EXHAUSTION,	"approaching TCP memory exhaustion",
	"Since memory exhaustion is a highly unstable state, adjust TCP memory-related tunables to avoid exhaustion" },
{ TCP_MODERATE_RCVBUF_ENABLE, "match receive buffer size with throughput needs",
	"Since we are tuning rcvbuf max size, ensure auto-tuning of rcvbuf size for the connection is enabled to pick optimal rcvbuf size" },
{ TCP_NO_METRICS_SAVE_ENABLE, "disable TCP path metrics collection",
	"In low-memory situations, avoid saving per-path TCP metrics to avoid allocations of 'struct tcp_metrics'" },
{ TCP_NO_METRICS_SAVE_DISABLE, "enable TCP path metrics collection",
	"Due to easing of memory strain, (re)-enable TCP metrics collection" },
{ TCP_MAX_ORPHANS_INCREASE,
			"increase max number of orphaned sockets",
			"" },
};

/* When TCP starts up, it calls nr_free_buffer_pages() and uses it to estimate
 * the values for tcp_mem[0-2].  The equivalent of this estimate can be
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
 * On startup tcp_mem[0-2] are ~4.6%,  6.25%  and  9.37% of nr_free_buffer_pages.
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
	const char *optionals[] = { "entry__tcp_sndbuf_expand", NULL };
	int pagesize;
	int err;

	err = bpftuner_bpf_open(tcp_buffer, tuner);
	if (err)
		return err;
	err = bpftuner_bpf_load(tcp_buffer, tuner, optionals);
	if (err)
		return err;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0)
		pagesize = 4096;
	bpftuner_bpf_var_set(tcp_buffer, tuner, kernel_page_size, pagesize);
	bpftuner_bpf_var_set(tcp_buffer, tuner, kernel_page_shift,
			     ilog2(pagesize));
	bpftuner_bpf_var_set(tcp_buffer, tuner, sk_mem_quantum, SK_MEM_QUANTUM);
	bpftuner_bpf_var_set(tcp_buffer, tuner, sk_mem_quantum_shift,
			     ilog2(SK_MEM_QUANTUM));
	bpftuner_bpf_var_set(tcp_buffer, tuner, nr_free_buffer_pages,
			     nr_free_buffer_pages(true));
	bpftuner_bpf_sample_add(tcp_buffer, tuner, rcv_space_sample);
	err = bpftuner_bpf_attach(tcp_buffer, tuner);
	if (err)
		return err;
	return bpftuner_tunables_init(tuner, TCP_BUFFER_NUM_TUNABLES, descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

static void update_lowmem_tunables(struct bpftuner *tuner,
				   struct bpftune_event *event,
				   bool lowmem)
{
	struct bpftunable *t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_NO_METRICS_SAVE);
	char *msg = lowmem ? "Due to low memory conditions, set '%s'\n" :
			     "Due to leaving low memory conditions, set '%s'\n";
	long needs_change = lowmem ? 0 : 1;
	long new_val = lowmem ? 1 : 0;
	long new[3];

	if (t->current_values[0] == needs_change) {
		new[0] = new_val;
		bpftuner_tunable_sysctl_write(tuner,
					      TCP_BUFFER_TCP_NO_METRICS_SAVE,
					      TCP_NO_METRICS_SAVE_ENABLE,
					      event->netns_cookie,
					      1, new, msg, t->desc.name);
	}
	t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE);
	if (t->current_values[0] == needs_change) {
		new[0] = new_val;
		bpftuner_tunable_sysctl_write(tuner,
					      TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE,
					      TCP_NO_METRICS_SAVE_ENABLE,
					      event->netns_cookie,
					      1, new, msg, t->desc.name);
	}
}

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	const char *lowmem = "normal memory conditions";
	const char *reason = "unknown reason";
	bool near_memory_exhaustion, under_memory_pressure, near_memory_pressure;
	int scenario = event->scenario_id;
	struct corr c = { 0 };
	long double corr = 0;
	struct bpftunable *t;
	const char *tunable;
	long new[3], old[3];
	struct corr_key key;
	int id;

	/* netns cookie not supported; ignore */
	if (event->netns_cookie == (unsigned long)-1)
		return;

	id = event->update[0].id;

	memcpy(new, event->update[0].new, sizeof(new));
	memcpy(old, event->update[0].old, sizeof(old));

	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for tcp_buffer_tuner\n", id);
		return;
	}
	near_memory_exhaustion = bpftuner_bpf_var_get(tcp_buffer, tuner,
						     near_memory_exhaustion);
	under_memory_pressure = bpftuner_bpf_var_get(tcp_buffer, tuner,
					            under_memory_pressure);
	near_memory_pressure = bpftuner_bpf_var_get(tcp_buffer, tuner,
						   near_memory_pressure);
	if (near_memory_exhaustion)
		lowmem = "near memory exhaustion";
	else if (under_memory_pressure)
		lowmem = "under memory pressure";
	else if (near_memory_pressure)
		lowmem = "near memory pressure";
	else {
		update_lowmem_tunables(tuner, event, false);
	}

	key.id = (__u64)id;
	key.netns_cookie = event->netns_cookie;

	if (!bpf_map_lookup_elem(tuner->corr_map_fd, &key, &c)) {
		corr = corr_compute(&c);
		bpftune_log(LOG_DEBUG, "covar for '%s' netns %ld (new %ld %ld %ld): %LF ; corr %LF\n",
			    tunable, key.netns_cookie, new[0], new[1], new[2],
			    covar_compute(&c), corr);
		if (corr > CORR_THRESHOLD && scenario == TCP_BUFFER_INCREASE)
			scenario = TCP_BUFFER_DECREASE_LATENCY;
	}
	switch (id) {
	case TCP_BUFFER_TCP_MEM:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      event->netns_cookie, 3, new,
"Due to %s change %s(min pressure max) from (%ld %ld %ld) -> (%ld %ld %ld)\n",
					     lowmem, tunable, old[0], old[1], old[2],
					     new[0], new[1], new[2]);
		if (near_memory_exhaustion)
			update_lowmem_tunables(tuner, event, true);
		break;
	case TCP_BUFFER_TCP_WMEM:
	case TCP_BUFFER_TCP_RMEM:
		switch (scenario) {
		case TCP_BUFFER_INCREASE:
			reason = "need to increase max buffer size to maximize throughput";
			break;
		case TCP_BUFFER_DECREASE:
			reason = lowmem;
			break;
		case TCP_BUFFER_DECREASE_LATENCY:
			reason = "correlation between buffer size increase and latency";
			new[2] = BPFTUNE_SHRINK_BY_DELTA(old[2]);
			/* ensure we do not shrink too far */
			if (new[2] <= new[1])
				return;
			break;
		}
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      event->netns_cookie, 3, new,
"Due to %s change %s(min default max) from (%ld %ld %ld) -> (%ld %ld %ld)\n",
					      reason, tunable,
					      old[0], old[1], old[2],
					      new[0], new[1], new[2]);
		break;
	case TCP_BUFFER_TCP_MAX_ORPHANS:
		break;
	}
	if (id == TCP_BUFFER_TCP_RMEM) {
		t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_MODERATE_RCVBUF);

		if (t->current_values[0] != 1) {
			new[0] = 1;
			bpftuner_tunable_sysctl_write(tuner,
						      TCP_BUFFER_TCP_MODERATE_RCVBUF,
						      TCP_MODERATE_RCVBUF_ENABLE,
						      event->netns_cookie, 1, new,
"Because we are changing rcvbuf parameters, set '%s' to auto-tune receive buffer size to match the size required by the path for full throughput.\n",
						      t->desc.name);
		}


	}
}
