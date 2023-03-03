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

for TUNER in neigh_table ; do

 # gc_thresh3 is not namespaced...

 for NS in global ; do
  for TBL in arp_cache ndisc_cache ; do
 
   test_start "$0|neigh table legacy test ($NS netns): does filling $TBL make it grow?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -dsL &" true

   sleep $SLEEPTIME

   if [[ $NS != "global" ]]; then
	PREFIX_CMD="ip netns exec $NETNS "
        INTF=$VETH1
   else
	PREFIX_CMD=""
	INTF=$VETH2
   fi	
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh3 128

   for ((i=3; i < 255; i++ ))
   do
      ipaddr="192.168.168.${i}"
      ih=$(printf '%x' $i)
      ip6addr="fd::${ih}"
      macaddr="de:ad:be:ef:de:${ih}"
      if [[ $TBL == "arp_cache" ]]; then
	$PREFIX_CMD ip neigh add $ipaddr lladdr $macaddr dev $INTF
      else
	$PREFIX_CMD ip neigh add $ip6addr lladdr $macaddr dev $INTF
      fi
   done
   echo "Following changes were made:"
   set +e  
   grep bpftune $LOGFILE
   set -e
   grep "updated gc_thresh3 for $TBL" $LOGFILE
   test_pass
  done
 done
done

test_cleanup

test_exit
