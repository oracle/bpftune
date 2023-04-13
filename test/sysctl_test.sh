#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates.
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

# run sysctl test

. ./test_lib.sh


SLEEPTIME=10

for TUNER in neigh_table ; do

   test_start "$0|sysctl test: does setting sysctl switch off tuner?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -s &" true

   sleep $SETUPTIME
   for SYSCTL in net.ipv4.neigh.default.gc_thresh1 kernel.core_pattern ; do
	val="$(sysctl -qn $SYSCTL)"
	sysctl -qw ${SYSCTL}="${val}"
   done
   sleep $SLEEPTIME
   grep "modified sysctl" $TESTLOG_LAST
   test_pass

   test_cleanup
done

test_exit
