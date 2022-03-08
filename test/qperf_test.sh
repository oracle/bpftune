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

 for CLIENT_OPTS in tcp_bw tcp_lat ; do
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

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $QPERF &"
	if [[ $MODE == "test" ]]; then
		test_run_cmd_local "$BPFTUNE &"
	fi
	test_run_cmd_local \
	    "$QPERF -v $ADDR -uu -oo msg_size:1:64k:*4 -vu ${CLIENT_OPTS}" true
	sleep $SLEEPTIME
	results=$(grep -E "bw.*=|lat.*=" ${CMDLOG} | awk '{print $3}')
	units=$(grep -E "bw.*=|lat.*=" ${CMDLOG} | awk '{print $4}' |head -1)
	if [[ $MODE == "baseline" ]]; then
		read -r -a baseline_results <<< $results
		echo "" > ${CMDLOG}
	else
		read -r -a test_results <<< $results
	fi
   done

   for (( i=0; i < ${#baseline_results[@]}; i++ ))
   do
	printf "Results $i ${CLIENT_OPTS} (${units}): "
	case $CLIENT_OPTS in
	tcp_bw)
		if [[ ${baseline_results[$i]} -gt ${test_results[$i]} ]]; then	
			bold "Warning: baseline ${baseline_results[$i]} > test (${test_results[$i]})"
		else
			echo "baseline (${baseline_results[$i]}) < test (${test_results[$i]})"
		fi
		;;

	tcp_lat)
		if [[ ${baseline_results[$i]} -lt ${test_results[$i]} ]]; then
			bold "Warning: baseline ${baseline_results[$i]} < test (${test_results[$i]})"
		else
			echo "baseline (${baseline_results[$i]}) > test (${test_results[$i]})"
		fi
		;;	
	esac
   done

   test_pass

   test_cleanup
 done
 done
done

test_exit
