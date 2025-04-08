#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License v2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 021110-1307, USA.
#

. ./test_lib.sh


SETUPTIME=10

CWD=$(dirname $0)

test_start "$0|pcp pmda test: are tunables available"

if [[ -n "$DBPMDA_CMD" ]]; then
	test_run_cmd_local "$BPFTUNE -s &" true
	sleep $SETUPTIME
	cat<<EOF | $DBPMDA_CMD -n ${CWD}/../src/pcp/pmns-for-testing
	open pipe ${CWD}/../src/pcp/pmdabpftune.python
	fetch bpftune.tcp_conn.net.ipv4.tcp_congestion_control
	fetch bpftune.ip_frag.net.ipv4.ipfrag_high_thresh
	fetch bpftune.tcp_buffer.net.ipv4.tcp_rmem
EOF
	test_pass
else
	echo "skipping as dbpmda is not available"
	test_pass
fi

test_cleanup
test_exit
