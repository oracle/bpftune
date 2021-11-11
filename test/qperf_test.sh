#!/usr/bin/bash
#
# Copyright (c) 2021, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# run qperf test

. ./test_lib.sh


for FAMILY in ipv4 ipv6 ; do

SLEEPTIME=0.5

for LATENCY in "" "latency 20ms" ; do
 if [[ -n "$LATENCY" ]]; then
  TIMEOUT=60
 else
  TIMEOUT=30
 fi

 for CLIENT_OPTS in bw lat ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|qperf test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   test_setup "true"

   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $QPERF &"
	if [[ $MODE == "test" ]]; then
		test_run_cmd_local "$TCPTUNE &"
	fi
	test_run_cmd_local "$QPERF -v $ADDR tcp_${CLIENT_OPTS}" true
	sleep $SLEEPTIME
   done
   grep -E "${CLIENT_OPTS}.*=" ${CMDLOG}

   test_pass

   test_cleanup
 done
 done
done

test_exit
