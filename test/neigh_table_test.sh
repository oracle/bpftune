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

 for TBL in arp_cache ndisc_cache ; do
 
   test_start "$0|neigh table test: does filling $TBL make it grow?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SLEEPTIME

   ip ntable change name $TBL dev $VETH2 thresh3 128

   for ((i=3; i < 255; i++ ))
   do
      ipaddr="192.168.168.${i}"
      ih=$(printf '%x' $i)
      ip6addr="fd::${ih}"
      macaddr="de:ad:be:ef:de:${ih}"
      if [[ $TBL == "arp_cache" ]]; then
	ip neigh add $ipaddr lladdr $macaddr dev $VETH2
      else
	ip neigh add $ip6addr lladdr $macaddr dev $VETH2
      fi
   done
   ip neigh show dev $VETH2
   grep "updated gc_thresh3 for $TBL" $TESTLOG_LAST
   test_pass

 done
done

test_cleanup

test_exit
