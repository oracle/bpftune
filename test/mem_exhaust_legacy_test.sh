#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

PORT=5201

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=50

for FAMILY in ipv4 ipv6 ; do

   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|mem legacy test to $ADDR:$PORT $FAMILY $MAX_CONN conn"

   mem_orig=($(sysctl -n net.ipv4.tcp_mem))

   mem_test=($(echo 50 100 100))
   test_setup true

   sysctl -w net.ipv4.tcp_mem="${mem_test[0]} ${mem_test[1]} ${mem_test[2]}"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -L -a tcp_buffer_tuner.so -s &" true
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
	fi
	set +e
	test_run_cmd_local "$IPERF3 -fm -P $MAX_CONN -p $PORT -c $ADDR " true
	set -e

	sleep $SLEEPTIME
   done

   mem_post=($(sysctl -n net.ipv4.tcp_mem))
   sysctl -w net.ipv4.tcp_mem="${mem_orig[0]} ${mem_orig[1]} ${mem_orig[2]}"
   echo "mem before ${mem_test[0]} ${mem_test[1]} ${mem_test[2]}"
   echo "mem after ${mem_post[0]} ${mem_post[1]} ${mem_post[2]}"
   if [[ $MODE == "test" ]]; then
	echo "Following changes were made:"
	set +e
	grep bpftune $LOGFILE
	set -e
	if [[ "${mem_post[2]}" -gt ${mem_test[2]} ]]; then
		test_pass
	else
		test_cleanup
	fi
   fi

   test_cleanup
done

test_exit
