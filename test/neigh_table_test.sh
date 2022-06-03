#!/usr/bin/bash
#
# Copyright (c) 2022, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# run neigh table test

. ./test_lib.sh

SLEEPTIME=0.5

for TUNER in neigh_table ; do

 for NS in global $NETNS ; do
  for TBL in arp_cache ndisc_cache ; do
 
   test_start "$0|neigh table test ($NS netns): does filling $TBL make it grow?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SLEEPTIME

   if [[ $NETNS != "global" ]]; then
	PREFIX_CMD="ip netns exec $NETS "
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
   grep "updated gc_thresh3 for $TBL" $TESTLOG_LAST
   test_pass
  done
 done
done

test_cleanup

test_exit
