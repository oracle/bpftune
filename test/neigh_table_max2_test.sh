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

# run neigh table test for multiple IPs which should expand
# max limit.

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1

for TUNER in neigh_table ; do

 # gc_thresh3 is not namespaced...

 for NS in global ; do
  for TBL in arp_cache ; do
 
   test_start "$0|neigh table test ($NS netns): do we adjust max value for $TBL with multiple IPs configured?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SETUPTIME

   if [[ $NS != "global" ]]; then
	PREFIX_CMD="ip netns exec $NETNS "
        INTF=$VETH1
   else
	PREFIX_CMD=""
	INTF=$VETH2
   fi	
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh1 32
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh2 64
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh3 128

   for ((i=3; i < 255; i++ ))
   do
      ipaddr="192.168.168.${i}"
      ih=$(printf '%x' $i)
      macaddr="de:ad:be:ef:de:${ih}"
      $PREFIX_CMD ip neigh replace $ipaddr lladdr $macaddr dev $INTF
   done

   # enough IPs to up max addr to 4 * 1024, > # of entries we add.
   $PREFIX_CMD ip addr add 192.168.167/24 dev $INTF
   $PREFIX_CMD ip addr add 192.168.166/24 dev $INTF
   $PREFIX_CMD ip addr add 192.168.165/24 dev $INTF

   for ((i=1; i < 10; i++ ))
   do
      for ((j=1; j < 254; j++ ))
      do
          ipaddr="224.1.${i}.${j}"
	  ih=$(printf '%x' $i)
	  jh=$(printf '%x' $j)
	  macaddr="01:00:5e:20:$ih:$jh"
	  $PREFIX_CMD ip neigh replace $ipaddr lladdr $macaddr dev $INTF
      done
   done
   grep "updated thresholds for $TBL table" $LOGFILE
   test_pass
  done
 done
done

test_cleanup

test_exit
