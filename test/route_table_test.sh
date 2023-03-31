#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# run neigh table test

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1

for TUNER in route_table ; do


 for NS in global $NETNS ; do
  for TBL in v6 ; do
 
   test_start "$0|route table test ($NS netns): does filling $TBL make it grow?"

   test_setup "true"

   if [[ $NS != "global" ]]; then
	PREFIX_CMD="ip netns exec $NETNS "
	OPREFIX_CMD=""
   else
	PREFIX_CMD=""
	OPREFIX_CMD="ip netns exec $NETNS"
   fi

   max_size_orig=($($PREFIX_CMD sysctl -n net.ipv6.route.max_size))
   thresh_orig=$($(PREFIX_CMD sysctl -n net.ipv6.route.gc_thresh))
   $PREFIX_CMD sysctl -w net.ipv6.route.gc_thresh=16
   $PREFIX_CMD sysctl -w net.ipv6.route.max_size=32

   test_run_cmd_local "$BPFTUNE -ds &" true

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
   sleep $SLEEPTIME
   echo "Following changes were made:"
   set +e  
   grep bpftune $LOGFILE
   set -e
   $PREFIX_CMD sysctl -w net.ipv6.route.max_size="$max_size_orig"
   $PREFIX_CMD sysctl -w net.ipv6.route.gc_thresh="$thresh_orig"
   grep "destination table nearly full" $LOGFILE
   test_pass
   test_cleanup
  done
 done
done

test_exit
