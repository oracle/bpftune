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

# run cleanup test

. ./test_lib.sh


SLEEPTIME=10

for TUNER in sysctl_tuner.so tcp_conn_tuner.so ; do

   test_start "$0|cleanup test: do old cgroup progs get cleaned up for $TUNER?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -s &" true

   sleep $SETUPTIME
   pkill -9 bpftune
   dangling_before=$(bpftool prog |grep bpftune)
   if [[ -z "$dangling_before" ]]; then
	echo "No dangling progs"
	test_pass
   else
   	test_run_cmd_local "$BPFTUNE -ds &" true
	sleep $SETUPTIME
	grep "detaching old BPF program" $TESTLOG_LAST
	pkill -TERM bpftune
	sleep $SETUPTIME
	set +e
	dangling_after=$(bpftool prog|grep bpftune)
	set -e
	if [[ -n "$dangling_after" ]]; then
		echo "progs still attached: $dangling_after"
	else
		test_pass
	fi
   fi
   test_cleanup
done

test_exit
