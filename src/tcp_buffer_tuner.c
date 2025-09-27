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
{ TCP_BUFFER_NET_CORE_HIGH_ORDER_ALLOC_DISABLE, BPFTUNABLE_SYSCTL, "net.core.high_order_alloc_disable",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_SYNCOOKIES, BPFTUNABLE_SYSCTL | BPFTUNABLE_OPTIONAL, "net.ipv4.tcp_syncookies",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_MAX_SYN_BACKLOG, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_max_syn_backlog",
	BPFTUNABLE_NAMESPACED, 1 },
{ TCP_BUFFER_TCP_MAX_ORPHANS, BPFTUNABLE_SYSCTL, "net.ipv4.tcp_max_orphans",
	0, 1 },
};

static struct bpftunable_scenario scenarios[] = {
	BPFTUNABLE_SCENARIO(TCP_BUFFER_INCREASE,
			"need to increase TCP buffer size(s)",
	"Need to increase buffer size(s) to maximize throughput"),
	BPFTUNABLE_SCENARIO(TCP_BUFFER_DECREASE,
			"need to decrease TCP buffer size(s)",
	"Need to decrease buffer size(s) to reduce memory utilization"),
	BPFTUNABLE_SCENARIO(TCP_BUFFER_DECREASE_LATENCY,
			"need to decrease TCP buffer size due to latency",
	"Latency is starting to correlate with buffer size increases, so decrease buffer size to avoid this effect"),
	BPFTUNABLE_SCENARIO(TCP_MEM_PRESSURE,
			"approaching TCP memory pressure",
	"Since memory pressure/exhaustion are unstable system states, adjust tcp memory-related tunables"),
	BPFTUNABLE_SCENARIO(TCP_MEM_EXHAUSTION,
			"approaching TCP memory exhaustion",
	"Since memory exhaustion is a highly unstable state, adjust TCP memory-related tunables to avoid exhaustion"),
	BPFTUNABLE_SCENARIO(TCP_MODERATE_RCVBUF_ENABLE,
			"match receive buffer size with throughput needs",
	"Since we are tuning rcvbuf max size, ensure auto-tuning of rcvbuf size for the connection is enabled to pick optimal rcvbuf size"),
	BPFTUNABLE_SCENARIO(TCP_LOW_MEM_ENTER_ENABLE,
			"set tunable on entering low-memory state",
	"In low-memory situations, avoid activities like skb high order allocations, per-path TCP metric collection which can lead to overheads"),
	BPFTUNABLE_SCENARIO(TCP_LOW_MEM_LEAVE_DISABLE,
			"unset tunable set earlier in low-memory state",
	"Due to easing of memory strain, unset tunables to allow skb high order allocations, (re)-enable TCP metrics collection etc"),
	BPFTUNABLE_SCENARIO(TCP_MAX_SYN_BACKLOG_INCREASE,
			"increase maximum syn backlog under load since syncookies are disabled",
	"Due to the fact that syncookies are disabled and we are seeing a large number of legitimate-seeming TCP connections, increase TCP maximum SYN backlog queue length"),
	BPFTUNABLE_SCENARIO(TCP_MAX_SYN_BACKLOG_DECREASE,
			"decrease maximum syn backlog due to large numbers of uncompleted connections",
	"A large number of connection requests (SYNs) uncorrelated with connection establishment suggest a more cautious approach to handling pending connections to avoid Denial of Service attacks"),
	BPFTUNABLE_SCENARIO(TCP_SYNCOOKIES_ENABLE,
			"enable syncookies as furthern SYN backlog increases do not help",
	"SYN flood conditions have been detected, but further increases to SYN backlog are not advisable; try using syncookies instead"),
	BPFTUNABLE_SCENARIO(TCP_SYNCOOKIES_DISABLE,
			"disable syncookies as they are ineffective",
	"TCP syncookies are not effective; none have been validated successfully"),
	BPFTUNABLE_SCENARIO(TCP_MAX_ORPHANS_INCREASE,
			"increase max number of orphaned sockets",
	""),
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
	/* on some platforms, these functions are inlined */
	const char *optionals[] = { "entry__tcp_sndbuf_expand",
				    "entry__tcp_syn_flood_action",
				    NULL };
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
	bpftuner_bpf_sample_add(tcp_buffer, tuner, syn_flood_action_sample);
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
	enum tcp_buffer_scenarios scenario = lowmem ? TCP_LOW_MEM_ENTER_ENABLE :
						      TCP_LOW_MEM_LEAVE_DISABLE;
	long needs_change = lowmem ? 0 : 1;

	long new_val = lowmem ? 1 : 0;
	long new[3];

	if (t->current_values[0] == needs_change) {
		new[0] = new_val;
		bpftuner_tunable_sysctl_write(tuner,
					      TCP_BUFFER_TCP_NO_METRICS_SAVE,
					      scenario,
					      event->netns_cookie,
					      1, new, msg, t->desc.name);
	}
	t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE);
	if (t->current_values[0] == needs_change) {
		new[0] = new_val;
		bpftuner_tunable_sysctl_write(tuner,
					      TCP_BUFFER_TCP_NO_SSTHRESH_METRICS_SAVE,
					      scenario,
					      event->netns_cookie,
					      1, new, msg, t->desc.name);
	}
	t = bpftuner_tunable(tuner, TCP_BUFFER_NET_CORE_HIGH_ORDER_ALLOC_DISABLE);
	if (t->current_values[0] == needs_change) {
		new[0] = new_val;
		bpftuner_tunable_sysctl_write(tuner,
					      TCP_BUFFER_NET_CORE_HIGH_ORDER_ALLOC_DISABLE,
					      scenario,
					      event->netns_cookie,
					      1, new, msg, t->desc.name);
	}
	t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_MAX_SYN_BACKLOG);
	if (lowmem) {
		new[0] = BPFTUNE_SHRINK_BY_DELTA(t->current_values[0]);
		if (new[0] < TCP_SYN_BACKLOG_MIN)
			return;
	} else {
		new[0] = BPFTUNE_GROW_BY_DELTA(t->current_values[0]);
	}

	bpftuner_tunable_sysctl_write(tuner,
				      TCP_BUFFER_TCP_MAX_SYN_BACKLOG,
				      scenario,
				      event->netns_cookie,
				      1, new, msg, t->desc.name);
}

bool near_memory_exhaustion, under_memory_pressure, near_memory_pressure;

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	const char *lowmem = "normal memory conditions";
	const char *reason = "unknown reason";
	int scenario = event->scenario_id;
	long goodcookies, badcookies;
	bool prev_lowmem = false;
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
	prev_lowmem = under_memory_pressure || near_memory_exhaustion;

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
	else if (prev_lowmem)
		update_lowmem_tunables(tuner, event, false);

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
		if (id != TCP_BUFFER_TCP_RMEM)
			break;
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
		break;
	case TCP_BUFFER_TCP_MAX_SYN_BACKLOG:
		if (scenario != TCP_MAX_SYN_BACKLOG_INCREASE)
			break;
		t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_SYNCOOKIES);
		if (t && t->current_values[0] > 0 &&
		    !bpftune_netstat_read(event->netns_cookie, AF_INET, NULL,
					  "SyncookiesRecv", &goodcookies) &&
		    !bpftune_netstat_read(event->netns_cookie, AF_INET, NULL,
					  "SyncookiesFailed", &badcookies)) {

			/* syncookies are enabled; are they effective? compare good/bad counts.
			 * If none are good, syncookies are not really effective and we would
			 * do better to rely on syn backlog increases.
			 */
			if (badcookies >= TCP_SYNCOOKIES_BAD_COUNT &&
			    !goodcookies) {
				new[0] = 0;
				bpftuner_tunable_sysctl_write(tuner, TCP_BUFFER_TCP_SYNCOOKIES,
							      TCP_SYNCOOKIES_DISABLE,
							      event->netns_cookie, 1, new,
"Due to receiving %d invalid syncookies and no valid ones, disable '%s' as they are ineffective under current network conditions\n",
							      badcookies,
							      t->desc.name);
				break;

			}
		} else if (t && (under_memory_pressure || near_memory_exhaustion)) {
			new[0] = 1;
			bpftuner_tunable_sysctl_write(tuner, TCP_BUFFER_TCP_SYNCOOKIES,
						      TCP_SYNCOOKIES_ENABLE,
						      event->netns_cookie, 1, new,
"Due to low memory conditions under SYN flood, enable '%s' rather than increasing max SYN backlog\n",
						      t->desc.name);
			break;
		}
		/* Do not increase - rather decrease - max syn backlog and set other lowmem tunables */
		if (near_memory_exhaustion) {
			update_lowmem_tunables(tuner, event, true);
			break;
		}
		t = bpftuner_tunable(tuner, TCP_BUFFER_TCP_MAX_SYN_BACKLOG);
		key.id = (__u64)id;
		key.netns_cookie = event->netns_cookie;
		if (!bpf_map_lookup_elem(tuner->corr_map_fd, &key, &c)) {
			corr = corr_compute(&c);
			bpftune_log(LOG_DEBUG, "covar for '%s' netns %ld (new %ld): %LF ; corr %LF\n",
				    tunable, key.netns_cookie, new[0],
				    covar_compute(&c), corr);
			if (c.n > CORR_MIN_SAMPLES  && corr < CORR_THRESHOLD) {
				new[0] = BPFTUNE_SHRINK_BY_DELTA(old[0]);
				if (new[0] < TCP_SYN_BACKLOG_MIN)
					break;
				bpftuner_tunable_sysctl_write(tuner, TCP_BUFFER_TCP_MAX_SYN_BACKLOG,
							      TCP_MAX_SYN_BACKLOG_DECREASE,
							      event->netns_cookie, 1, new,
"Due to SYN flood not correlated with TCP connection acceptance - suggesting an attack - reduce '%s' from %ld -> %ld\n",
							      t->desc.name, old[0], new[0]);
				break;
			}
                }
		bpftuner_tunable_sysctl_write(tuner, TCP_BUFFER_TCP_MAX_SYN_BACKLOG,
					      TCP_MAX_SYN_BACKLOG_INCREASE,
					      event->netns_cookie, 1, new,
"Due to SYN flood events on a system with TCP syncookies disabled and no low memory issues, increase '%s'\n",
					      t->desc.name);
		break;
	case TCP_BUFFER_TCP_MAX_ORPHANS:
		break;
	}
}
