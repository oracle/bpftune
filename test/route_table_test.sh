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
	$PREFIX_CMD ip link set lo up
	ADDR=$VETH2_IPV6
        INTF=$VETH1
   else
	PREFIX_CMD=""
	ADDR=$VETH1_IPV6
	INTF=$VETH2
   fi
   $PREFIX_CMD ip link add bpftunelocal type dummy
   $PREFIX_CMD ip link set bpftunelocal up
   sleep $SLEEPTIME
   $PREFIX_CMD sysctl -w net.ipv6.conf.bpftunelocal.forwarding=1
   $PREFIX_CMD sysctl -w net.ipv6.conf.${INTF}.forwarding=1

   for ((i=3; i < 150; i++ ))
   do
      ih=$(printf '%x' $i)
      ip6addr="fd::${ih}01"
      $PREFIX_CMD ip addr add ${ip6addr}/120 dev bpftunelocal
   done

   $PREFIX_CMD ip addr
   max_size_orig=($($PREFIX_CMD sysctl -n net.ipv6.route.max_size))
   $PREFIX_CMD sysctl -w net.ipv6.route.max_size=32

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SETUPTIME

   for ((i=3; i < 150; i++ ))
   do
      ih=$(printf '%x' $i)
      ip6pfx="fd::${ih}00"
      ip6addr="fd::${ih}01"

      #$PREFIX_CMD ip -6 route add ${ip6pfx}/120 via $ADDR protocol ra
      $PREFIX_CMD route -6 add ${ip6pfx} gw $ADDR dev $INTF dyn
      set -e
      $PREFIX_CMD ping -6 -c 1 $ip6addr
      set +e
   done
   echo "Following changes were made:"
   set +e  
   grep bpftune $LOGFILE
   set -e
   #grep "table nearly full" $LOGFILE
   test_pass
    $PREFIX_CMD sysctl -w net.ipv6.route.max_size="$max_size_orig"
    $PREFIX_CMD ip link del dev bpftunelocal
    test_cleanup
  done
 done
done

test_exit
