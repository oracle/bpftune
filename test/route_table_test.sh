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

# run neigh table test

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=10

for TUNER in route_table ; do


 for NS in global $NETNS ; do
  for TBL in v6 ; do
 
   test_start "$0|route table test ($NS netns): does filling $TBL cache make it grow?"

   test_setup "true"

   if [[ $NS != "global" ]]; then
	PREFIX_CMD="ip netns exec $NETNS "
	OPREFIX_CMD=""
   else
	PREFIX_CMD=""
	OPREFIX_CMD="ip netns exec $NETNS"
   fi

   max_size_orig=($($PREFIX_CMD sysctl -n net.ipv6.route.max_size))
   thresh_orig=($($PREFIX_CMD sysctl -n net.ipv6.route.gc_thresh))
   $PREFIX_CMD sysctl -w net.ipv6.route.gc_thresh=16
   $PREFIX_CMD sysctl -w net.ipv6.route.max_size=32

   test_run_cmd_local "$BPFTUNE -s &" true

   sleep $SETUPTIME

   for ((i=1; i < 1024; i++ ))
   do
      $PREFIX_CMD ip link add bpftunelink${i} type dummy
      $PREFIX_CMD ip link set bpftunelink${i} up
   done
   for ((i=1; i < 1024; i++ ))
   do
      $PREFIX_CMD ip link del bpftunelink${i}
   done
   # wait for gc...
   sleep $SLEEPTIME
   sleep $SLEEPTIME
   sleep $SLEEPTIME
   sleep $SLEEPTIME
   max_size_post=($($PREFIX_CMD sysctl -n net.ipv6.route.max_size))
   $PREFIX_CMD sysctl -w net.ipv6.route.max_size="$max_size_orig"
   $PREFIX_CMD sysctl -w net.ipv6.route.gc_thresh="$thresh_orig"
   grep "change net.ipv6.route.max_size" $LOGFILE
   if [[ "$max_size_post" -gt "$max_size_orig" ]]; then
       test_pass
   fi
   test_cleanup
  done
 done
done

test_exit
