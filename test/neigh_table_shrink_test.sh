#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2026, Oracle and/or its affiliates.
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

# run neigh table shrink test

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1

for TUNER in neigh_table ; do

 # gc_thresh3 is not namespaced...

 for NS in global ; do
  for TBL in arp_cache ndisc_cache ; do

   test_start "$0|neigh table shrink test ($NS netns): does emptying $TBL make it shrink?"

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
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh1 512
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh2 2048
   $PREFIX_CMD ip ntable change name $TBL dev $INTF thresh3 4096

   for ((i=3; i < 255; i++ ))
   do
      ipaddr="192.168.168.${i}"
      ih=$(printf '%x' $i)
      ip6addr="fd::${ih}"
      macaddr="de:ad:be:ef:de:${ih}"
      if [[ $TBL == "arp_cache" ]]; then
	$PREFIX_CMD ip neigh replace $ipaddr lladdr $macaddr dev $INTF
      else
	$PREFIX_CMD ip neigh replace $ip6addr lladdr $macaddr dev $INTF
      fi
   done

   for ((i=3; i < 255; i++ ))
   do
      ipaddr="192.168.168.${i}"
      ih=$(printf '%x' $i)
      ip6addr="fd::${ih}"
      macaddr="de:ad:be:ef:de:${ih}"
      if [[ $TBL == "arp_cache" ]]; then
	$PREFIX_CMD ip neigh del $ipaddr lladdr $macaddr dev $INTF
      else
	$PREFIX_CMD ip neigh del $ip6addr lladdr $macaddr dev $INTF
      fi
   done
   grep "reduced thresholds for $TBL table" $LOGFILE
   test_pass
  done
 done
done

test_cleanup

test_exit
