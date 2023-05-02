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
#include <time.h>
#include <linux/netlink.h>
#include <libnl3/netlink/route/neightbl.h>
#include "neigh_table_tuner.h"
#include "neigh_table_tuner.skel.h"
#include "neigh_table_tuner.skel.legacy.h"

struct neigh_table_tuner_bpf *skel;

static struct bpftunable_desc descs[] = {
{ NEIGH_TABLE_IPV4_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
  		"net.ipv4.neigh.default.gc_interval",	false,	1 },
{ NEIGH_TABLE_IPV4_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_stale_time",	true,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh1",	false,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh2",	false,	1, },
{ NEIGH_TABLE_IPV4_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv4.neigh.default.gc_thresh3",	false,	1, },
{ NEIGH_TABLE_IPV6_GC_INTERVAL,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_interval",   false,	1 },
{ NEIGH_TABLE_IPV6_GC_STALE_TIME,	BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_stale_time", true, 1, },
{ NEIGH_TABLE_IPV6_GC_THRESH1,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh1",    false, 1, },
{ NEIGH_TABLE_IPV6_GC_THRESH2,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh2",    false, 1, },
{ NEIGH_TABLE_IPV6_GC_THRESH3,		BPFTUNABLE_SYSCTL,
		"net.ipv6.neigh.default.gc_thresh3",    false, 1, },
};

static struct bpftunable_scenario scenarios[] = {
{ NEIGH_TABLE_FULL,	"neighbour table nearly full",
		"neighbour table is nearly full, preventing new entries from being added." },
};

int init(struct bpftuner *tuner)
{
	bpftuner_bpf_init(neigh_table, tuner, NULL);
	return bpftuner_tunables_init(tuner, ARRAY_SIZE(descs), descs,
				      ARRAY_SIZE(scenarios), scenarios);
}

void fini(struct bpftuner *tuner)
{
	bpftune_log(LOG_DEBUG, "calling fini for %s\n", tuner->name);
	bpftuner_bpf_fini(tuner);
}

static int set_gc_thresh3(struct bpftuner *tuner, struct tbl_stats *stats)
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
	struct nl_msg *m = NULL, *parms = NULL;
	int new_gc_thresh3 = 0;
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

	new_gc_thresh3 = BPFTUNE_GROW_BY_DELTA(stats->max);
	NLA_PUT_U32(m, NDTA_THRESH3, new_gc_thresh3);

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

nla_put_failure:
out:
	if (parms)
		nlmsg_free(parms);
	if (m)
		nlmsg_free(m);
	nl_socket_free(sk);

	if (ret < 0) {
		bpftune_log(LOG_ERR, "could not change neightbl for %s : %s\n",
			    stats->dev, strerror(-ret));
	} else {
		bpftuner_tunable_update(tuner, tunable, NEIGH_TABLE_FULL, 0,
"updated gc_thresh3 for %s table, dev '%s' (ifindex %d) from %d to %d\n",
			    tbl_name, stats->dev, stats->ifindex,
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
		set_gc_thresh3(tuner, stats);
		bpftune_cap_drop();
		break;
	default:
		return;
	}
}
