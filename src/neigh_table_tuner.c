#include <libbpftune.h>
#include <time.h>
#include <linux/netlink.h>
#include <libnl3/netlink/route/neightbl.h>
#include "neigh_table_tuner.h"
#include "neigh_table_tuner.skel.h"

struct neigh_table_tuner_bpf *skel;

struct bpftunable_desc descs[] = {
{ NEIGH_TABLE_IPV4_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
  		"net.ipv4.neigh.default.gc_interval",	1 },
{ NEIGH_TABLE_IPV4_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_stale_time",	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh1",	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh2",	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh3",	1, },
{ NEIGH_TABLE_IPV6_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_interval",   1 },
{ NEIGH_TABLE_IPV6_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_stale_time", 1, },
{ NEIGH_TABLE_IPV6_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh1",    1, },
{ NEIGH_TABLE_IPV6_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh2",    1, },
{ NEIGH_TABLE_IPV6_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh3",    1, },
};

int init(struct bpftuner *tuner, int ringbuf_map_fd)
{
	bpftuner_bpf_init(neigh_table, tuner, ringbuf_map_fd);
	return bpftuner_tunables_init(tuner, NEIGH_TABLE_NUM_TUNABLES, descs);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

static int set_gc_thresh3(struct tbl_stats *stats)
{
	char *tbl_name = stats->family == AF_INET ? "arp_cache" : "ndisc_cache";
	struct rtnl_neightbl *old = NULL, *new = NULL;
	struct nl_cache *cache;
	/* Open raw socket for the NETLINK_ROUTE protocol */
	struct nl_sock *nl_sock = nl_socket_alloc();
	int ret;

	if (!nl_sock) {
		bpftune_log(LOG_ERR, "failed to alloc netlink socket\n");
		return -1;
	}
	nl_connect(nl_sock, NETLINK_ROUTE);

	ret = rtnl_neightbl_alloc_cache(nl_sock, &cache);
	if (ret) {
		bpftune_log(LOG_ERR, "could not alloc neightbl cache: %s\n",
			    strerror(-ret));
		goto out;
	}
	old = rtnl_neightbl_get(cache, tbl_name, stats->ifindex);
	if (ret) {
		bpftune_log(LOG_ERR, "could not alloc neightbl cache: %s\n",
			    strerror(-ret));
		goto out;
	}
	new = rtnl_neightbl_alloc();
	rtnl_neightbl_set_family(new, stats->family);
	rtnl_neightbl_set_name(new, tbl_name);
	rtnl_neightbl_set_dev(new, stats->ifindex);
	rtnl_neightbl_set_gc_tresh3(new, stats->max + 1);

	ret = rtnl_neightbl_change(nl_sock, old, new);
	if (ret) {
		bpftune_log(LOG_ERR, "could not change neightbl for '%s': %s\n",
			    stats->dev, strerror(-ret));
	} else {
		bpftune_log(LOG_DEBUG, "updated gc_thresh3 for '%s' table, dev '%s' (ifindex %d)\n",
			    tbl_name, stats->dev, stats->ifindex);
	}
	
out:
	nl_socket_free(nl_sock);
	rtnl_neightbl_put(old);
	rtnl_neightbl_put(new);

	return ret;
}		

void event_handler(struct bpftuner *tuner, struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct tbl_stats *tbl_stats = (struct tbl_stats *)&event->raw_data;
	int ret;

	bpftune_log(LOG_DEBUG, "got scenario %d for tuner %s\n",
		    event->scenario_id, tuner->name);
	ret = set_gc_thresh3(tbl_stats);

	bpftune_log(LOG_DEBUG,
		    "neigh_create: dev: %s tbl family %d entries %d (%d gc) max %d ret: %d\n",
		    tbl_stats->dev, tbl_stats->family, tbl_stats->entries,
		    tbl_stats->gc_entries, tbl_stats->max, ret);
}
