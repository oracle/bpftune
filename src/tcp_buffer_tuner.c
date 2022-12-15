#include <libbpftune.h>
#include "tcp_buffer_tuner.h"
#include "tcp_buffer_tuner.skel.h"

#include <unistd.h>

struct tcp_buffer_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ TCP_BUFFER_TCP_WMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_wmem",	true, 3 },
{ TCP_BUFFER_TCP_RMEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_rmem",	true, 3 },
{ TCP_BUFFER_TCP_MEM,	BPFTUNABLE_SYSCTL, "net.ipv4.tcp_mem",	false, 3 },
{ TCP_BUFFER_TCP_MAX_ORPHANS,
			BPFTUNABLE_SYSCTL, "net.ipv4.tcp_max_orphans",
								false, 1 },
{ NETDEV_MAX_BACKLOG,	BPFTUNABLE_SYSCTL, "net.core.netdev_max_backlog",
								false, 1 },
};

static struct bpftunable_scenario scenarios[] = {
{ TCP_BUFFER_INCREASE,	"need to increase TCP buffer size(s)",
	"Need to increase buffer size(s) to maximize throughput" },
{ TCP_BUFFER_DECREASE,	"Need to decrease TCP buffer size(s)",
	"Need to decrease buffer size(s) to reduce memory utilization" },
{ TCP_MEM_PRESSURE,	"approaching TCP memory pressure",
	"Since memory pressure/exhaustion are unstable system states, adjust tcp memory-related tunables" },
{ TCP_MEM_EXHAUSTION,	"approaching TCP memory exhaustion",
	"Since memory exhaustion is a highly unstable state, adjust TCP memory-related tunables to avoid exhaustion" },
{ TCP_MAX_ORPHANS_INCREASE,
			"increase max number of orphaned sockets",
			"" },
{ NETDEV_MAX_BACKLOG_INCREASE,
			"increase max backlog for received packets",
			"" },
{ NETDEV_MAX_BACKLOG_DECREASE,
			"decrease max backlog for received packets",
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
 */

int get_from_file(FILE *fp, const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int ret;

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

long nr_free_buffer_pages(bool initial)
{
	FILE *fp = fopen("/proc/zoneinfo", "r");
	unsigned long nr_pages = 0;

	if (!fp) {
		bpftune_log(LOG_DEBUG, "could not open /proc/zoneinfo: %s\n", strerror(errno));
		return 0;
	}	
	while (!feof(fp)) {
		long managed = 0, high = 0, free = 0, node;
		char zone[128] = {};

		if (get_from_file(fp, "Node %d, zone %s", &node, zone) < 0)
			break;
		if (strcmp(zone, "Normal") != 0)
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
	fclose(fp);

	return nr_pages;
}

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	struct tcp_buffer_tuner_bpf *skel;
	int pagesize;

	bpftuner_bpf_open(tcp_buffer, tuner, ringbuf_map_fd);
	bpftuner_bpf_load(tcp_buffer, tuner, ringbuf_map_fd);

	skel = tuner->skel;

	pagesize = sysconf(_SC_PAGESIZE);
	if (pagesize < 0)
		pagesize = 4096;
	skel->bss->kernel_page_size = pagesize;
	skel->bss->kernel_page_shift = ilog2(pagesize);
	skel->bss->sk_mem_quantum = SK_MEM_QUANTUM;
	skel->bss->sk_mem_quantum_shift = ilog2(SK_MEM_QUANTUM);
	skel->bss->nr_free_buffer_pages = nr_free_buffer_pages(true);
	bpftune_log(LOG_DEBUG,
		    "set pagesize/shift to %d/%d; sk_mem_quantum/shift %d/%d\n",
		    pagesize, skel->bss->kernel_page_shift, SK_MEM_QUANTUM,
		    skel->bss->sk_mem_quantum_shift);
	bpftune_log(LOG_DEBUG,
		    "set nr_free_buffer_pages to %ld\n", skel->bss->nr_free_buffer_pages);
	bpftuner_bpf_attach(tcp_buffer, tuner, ringbuf_map_fd);
	return bpftuner_tunables_init(tuner, TCP_BUFFER_NUM_TUNABLES, descs,
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
	struct tcp_buffer_tuner_bpf *skel = tuner->skel;
	const char *lowmem = "normal memory conditions";
	const char *reason = "unknown reason";
	int scenario = event->scenario_id;
	const char *tunable;
	long new[3], old[3];
	int netns_fd = 0;
	int id;

	id = event->update[0].id;

	memcpy(new, event->update[0].new, sizeof(new));
	memcpy(old, event->update[0].old, sizeof(old));
	
	if (event->netns_cookie) {
		netns_fd = bpftune_netns_fd_from_cookie(event->netns_cookie);
		if (netns_fd < 0) {
			bpftune_log(LOG_DEBUG, "could not get netns fd for cookie %ld\n",
				    event->netns_cookie); 
			return;
		}
	}
	tunable = bpftuner_tunable_name(tuner, id);
	if (!tunable) {
		bpftune_log(LOG_DEBUG, "unknown tunable [%d] for tcp_buffer_tuner\n", id);
		return;
	}
	if (skel->bss->near_memory_exhaustion)
		lowmem = "near memory exhaustion";
	else if (skel->bss->under_memory_pressure)
		lowmem = "under memory pressure";
	else if (skel->bss->near_memory_pressure)
		lowmem = "near memory pressure";

	switch (id) {
	case TCP_BUFFER_TCP_MEM:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					     netns_fd, 3, new,
"Due to %s change %s(min pressure max) from (%d %d %d) -> (%d %d %d)\n",
					     lowmem, tunable, old[0], old[1], old[2],
					     new[0], new[1], new[2]);

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
		}
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					     netns_fd, 3, new,
"Due to %s change %s(min default max) from (%d %d %d) -> (%d %d %d)\n",
					      reason, tunable,
					      old[0], old[1], old[2],
					      new[0], new[1], new[2]);
		break;
	case NETDEV_MAX_BACKLOG:
		bpftuner_tunable_sysctl_write(tuner, id, scenario,
					      netns_fd, 1, new,
"Dropped more than 1/4 of the backlog queue size (%d) in last minute; "
"increase backlog queue size from %d -> %d to support faster network device.\n",
					      old[0], new[0]);
		break;
	case TCP_BUFFER_TCP_MAX_ORPHANS:
		break;
	}

	if (netns_fd)
		close(netns_fd);
}
