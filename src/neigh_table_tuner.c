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
#include <limits.h>
#include <time.h>
#include <linux/netlink.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/route/neightbl.h>
#include <libnl3/netlink/netlink.h>
#include "neigh_table_tuner.h"
#include "neigh_table_tuner.skel.h"
#include "neigh_table_tuner.skel.legacy.h"
#include "neigh_table_tuner.skel.nobtf.h"

/* Amount to multiply amount of possible unicast addresses by
 * to generate upper bound on size of neigh table for ifindex.
 * If it is a /24 IPv4 address for example, we get 256 * 4
 * or 1024 addresses, which matches the default.  We will however
 * scale for bigger networks, more IP addresses.
 */
#define NEIGH_TABLE_ADDR_FACTOR		4

#define NEIGH_TABLE_ADDR_MIN		256
#define NEIGH_TABLE_ADDR_MAX		INT_MAX


struct neigh_table_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ NEIGH_TABLE_IPV4_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
  		"net.ipv4.neigh.default.gc_interval",	0,	1 },
{ NEIGH_TABLE_IPV4_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_stale_time",	0,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh1",	0,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh2",	0,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh3",	0,	1, },
{ NEIGH_TABLE_IPV6_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_interval",   BPFTUNABLE_OPTIONAL,
								1 },
{ NEIGH_TABLE_IPV6_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_stale_time", BPFTUNABLE_OPTIONAL,
								1, },
{ NEIGH_TABLE_IPV6_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh1",    BPFTUNABLE_OPTIONAL,
								1, },
{ NEIGH_TABLE_IPV6_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh2",    BPFTUNABLE_OPTIONAL,
								1, },
{ NEIGH_TABLE_IPV6_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh3",    BPFTUNABLE_OPTIONAL,
								1, },
};

static struct bpftunable_scenario scenarios[] = {
{ NEIGH_TABLE_FULL,			"neighbour table nearly full",
		"neighbour table is nearly full, preventing new entries from being added." },
{ NEIGH_TABLE_GROWN_EXCESSIVELY,	"neighbour table grown excessively",
		"neighbour table increases are beyond what would be expected for the device given the number of IP addresses/prefixlens associated with it."},
};

int init(struct bpftuner *tuner)
{
	int err = bpftuner_bpf_init(neigh_table, tuner, NULL);

	if (err)
		return err;
	return bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

struct max_addr_info {
	unsigned int ifindex;
	int family;
	int num_addrs;
	int pending;
	long long max_tbl_size;
};

/* compute max # of table entries for an ifindex based upon the prefixlens
 * of addresses associated with it.  This means for devices with lots
 * of addresses configured/large address ranges we will dynamically adjust
 * max based on that.  Use NEIGH_TABLE_ADDR_FACTOR as multiplication
 * factor; for a device with a single /24 IPv4 adress it is
 * (256 * NEIGH_TABLE_ADDR_FACTOR) for example.
 */
static int valid_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifaddrmsg *ifa = msg ? NLMSG_DATA(hdr) : NULL;
	struct max_addr_info *i = arg;
	long max_addrs;
	int addrlen;

	if (!ifa)
		return NL_OK;
	if (ifa->ifa_index != i->ifindex ||
	    ifa->ifa_family != i->family)
		return NL_OK;
	switch (ifa->ifa_family) {
	case AF_INET:
		addrlen = 32;
		break;
	case AF_INET6:
		addrlen = 128;
		break;
	default:
		return NL_OK;
	}
	i->num_addrs++;
	if (addrlen - ifa->ifa_prefixlen >= 64) {
		max_addrs = NEIGH_TABLE_ADDR_MAX;
	} else {
		max_addrs = 1 << (addrlen - ifa->ifa_prefixlen);
		/* in case prefixlen == addrlen */
		if (max_addrs < NEIGH_TABLE_ADDR_MIN)
			max_addrs = NEIGH_TABLE_ADDR_MIN;
		max_addrs *= NEIGH_TABLE_ADDR_FACTOR;
		if (max_addrs > NEIGH_TABLE_ADDR_MAX)
			max_addrs = NEIGH_TABLE_ADDR_MAX;
	}
	bpftune_log(LOG_DEBUG, "computed max addrs of %ld given addrlen %d, prefixlen %d\n",
		    max_addrs, addrlen, ifa->ifa_prefixlen);
	i->max_tbl_size += max_addrs;
	if (i->max_tbl_size > NEIGH_TABLE_ADDR_MAX)
		i->max_tbl_size = NEIGH_TABLE_ADDR_MAX;
	return NL_OK;	
}

static int finish_handler(__attribute__((unused))struct nl_msg *msg, void *arg)
{
	struct max_addr_info *i = arg;

	i->pending = 0;
	return NL_STOP;
}

static int increase_thresh(struct bpftuner *tuner, struct tbl_stats *stats)
{
	char *tbl_name = stats->family == AF_INET ? "arp_cache" : "ndisc_cache";
	/* Open raw socket for the NETLINK_ROUTE protocol */
	unsigned int tunable = stats->family == AF_INET ?
				NEIGH_TABLE_IPV4_GC_THRESH3 :
				NEIGH_TABLE_IPV6_GC_THRESH3;
	struct nl_sock *sk = nl_socket_alloc();
	struct ndtmsg ndt = {
                .ndtm_family = stats->family,
        };
	struct ifaddrmsg ifa = { .ifa_family = stats->family,
				 .ifa_index = stats->ifindex
	};
	struct max_addr_info max_addr_info = {	.family = stats->family,
						.ifindex = stats->ifindex,
						.max_tbl_size = 0,
						.num_addrs = 0,
						.pending  = 1,
	};
	struct nl_msg *m = NULL, *parms = NULL;
	struct nl_cb *cb = NULL;
	int new_gc_thresh1 = 0;
	int new_gc_thresh2 = 0;
	int new_gc_thresh3 = 0;
	bool updated = false;
	int ret;

	if (!sk) {
		bpftune_log(LOG_ERR, "failed to alloc netlink socket\n");
		return -ENOMEM;
	}
	ret = nl_connect(sk, NETLINK_ROUTE);
	if (ret) {
		bpftune_log(LOG_ERR, "nl_connect() failed: %d\n",
			    strerror(-ret));
		goto out;
	}

	/* First compute upper bound on gc_thresh3 based upon addresses
	 * configured for the ifindex
	 */
	m = nlmsg_alloc_simple(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
	if (!m) {
		ret = -ENOMEM;
		goto out;
	}
	ret = nlmsg_append(m, &ifa, sizeof(ifa), 0);
	if (ret)
		goto out;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		ret = -ENOMEM;
		goto out;
	}
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, &max_addr_info);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &max_addr_info);
	nl_send_auto_complete(sk, m);
	while (max_addr_info.pending > 0)
		nl_recvmsgs(sk, cb);
	nlmsg_free(m);
	m = NULL;

	bpftune_log(LOG_DEBUG, "%s: computed max tbl size of %ld for '%s'(ifindex %d) based on %d addresses\n",
		    tuner->name, max_addr_info.max_tbl_size,
		    stats->dev, stats->ifindex, max_addr_info.num_addrs);

	new_gc_thresh3 = BPFTUNE_GROW_BY_DELTA(stats->max);

	if (stats->max >= max_addr_info.max_tbl_size) {
		bpftuner_tunable_update(tuner, tunable,
					NEIGH_TABLE_GROWN_EXCESSIVELY, 0,
"can no longer update thresholds for gc_thresh[1-3] for table '%s' for device '%s' (ifindex %d) due to excessive size of table (we computed a reasonable max of %ld based on the prefixlens of the %d configured addresses). Current thresh1: %ld , thresh2: %ld , thresh3: %ld.\n",
                            tbl_name, stats->dev, stats->ifindex,
			    max_addr_info.max_tbl_size, max_addr_info.num_addrs,
                            stats->thresh1, stats->thresh2, stats->max);

		goto out;
	}

	/* it would be nice if we could simply call rtnl_neightbl_change()
	 * here but it has a bug; it doesn't set gc_thresh3 (copy-and-paste
	 * sets gc_thresh2 twice); instead roll our own...
	 */
	m = nlmsg_alloc_simple(RTM_SETNEIGHTBL, 0);
	if (!m) {
		ret = -ENOMEM;
		goto out;
	}

	ret = nlmsg_append(m, &ndt, sizeof(ndt), NLMSG_ALIGNTO);
	if (ret < 0)
		goto out;

	NLA_PUT_STRING(m, NDTA_NAME, tbl_name);

	NLA_PUT_U32(m, NDTA_THRESH3, new_gc_thresh3);
	new_gc_thresh2 = BPFTUNE_GROW_BY_DELTA(stats->thresh2);
	new_gc_thresh1 = BPFTUNE_GROW_BY_DELTA(stats->thresh1);
	NLA_PUT_U32(m, NDTA_THRESH2, new_gc_thresh2);
	NLA_PUT_U32(m, NDTA_THRESH1, new_gc_thresh1);

	parms = nlmsg_alloc();
	if (!parms) {
		ret = -ENOMEM;
		goto out;
	}

	NLA_PUT_U32(parms, NDTPA_IFINDEX, stats->ifindex);

	ret = nla_put_nested(m, NDTA_PARMS, parms);
	if (ret < 0)
		goto out;

	ret = nl_send_auto_complete(sk, m);
	if (ret < 0)
		bpftune_log(LOG_ERR, "nl_send_auto_complete() failed: %s\n",
			    strerror(-ret));

	updated = true;

nla_put_failure:
out:
	if (parms)
		nlmsg_free(parms);
	if (m)
		nlmsg_free(m);
	if (cb)
		nl_cb_put(cb);
	nl_socket_free(sk);

	if (ret < 0) {
		bpftune_log(LOG_ERR, "could not change neightbl for %s : %s\n",
			    stats->dev, strerror(-ret));
	} else if (updated) {
		bpftuner_tunable_update(tuner, tunable, NEIGH_TABLE_FULL, 0,
"updated thresholds for %s table, dev '%s' (ifindex %d) thresh1: %ld to %ld, thresh2: %ld to %ld, thresh3: %ld to %ld\n",
			    tbl_name, stats->dev, stats->ifindex,
			    stats->thresh1, new_gc_thresh1,
			    stats->thresh2, new_gc_thresh2,
			    stats->max, new_gc_thresh3);
	}
	return ret;
}		

void event_handler(struct bpftuner *tuner,
		   struct bpftune_event *event,
		   __attribute__((unused))void *ctx)
{
	struct tbl_stats *stats = (struct tbl_stats *)&event->raw_data;

	switch (event->scenario_id) {
	case NEIGH_TABLE_FULL:
		if (bpftune_cap_add())
			return;
		increase_thresh(tuner, stats);
		bpftune_cap_drop();
		break;
	default:
		return;
	}
}
