#!/usr/bin/bash
#
# Copyright (c) 2022, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# run iperf3 test with low rmem max, ensure tuner increases it.

PORT=5201

. ./test_lib.sh

SLEEPTIME=0.5
TIMEOUT=30

for FAMILY in ipv4 ipv6 ; do

 for CLIENT_OPTS in "" "-R" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|rmem test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   rmem_orig=($(sysctl -n net.ipv4.tcp_rmem))

   test_setup true

   rmem_orig_netns=($(ip netns exec $NETNS sysctl -n net.ipv4.tcp_rmem))

   sysctl -w net.ipv4.tcp_rmem="${rmem_orig[0]} ${rmem_orig[1]} ${rmem_orig[1]}"
   ip netns exec $NETNS sysctl -w net.ipv4.tcp_rmem="${rmem_orig_netns[0]} ${rmem_orig_netns[1]} ${rmem_orig_netns[1]}"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -d &"
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	sleep $SLEEPTIME
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -c $ADDR" true

	sresults=$(grep -E "sender" ${CMDLOG} | awk '{print $7}')
	rresults=$(grep -E "receiver" ${CMDLOG} | awk '{print $7}')
	units=$(grep -E "sender|receiver" ${CMDLOG} | awk '{print $8}' |head -1)

	if [[ $MODE == "baseline" ]]; then
                read -r -a sbaseline_results <<< $sresults
		read -r -a rbaseline_results <<< $rresults
                echo "" > ${CMDLOG}
        else
                read -r -a stest_results <<< $sresults
		read -r -a rtest_results <<< $rresults

        fi
	sleep $SLEEPTIME
   done

   rmem_post=($(sysctl -n net.ipv4.tcp_rmem))
   rmem_post_netns=($(ip netns exec $NETNS sysctl -n net.ipv4.tcp_rmem))
   sysctl -w net.ipv4.tcp_rmem="${rmem_orig[0]} ${rmem_orig[1]} ${rmem_orig[2]}"
   if [[ $MODE == "test" ]]; then
	if [[ "${rmem_post[2]}" -gt ${rmem_orig[1]} ]]; then
		echo "rmem before ${rmem_orig[1]} ; after ${rmem_post[2]}"

		if [[ "${rmem_post_netns[2]}" -gt ${rmem_orig_netns[1]} ]]; then
			echo "netns rmem before ${rmem_orig_netns[1]} ; after ${rmem_post_netns[2]}"
		else
			echo "netns rmem before ${rmem_orig_netns[1]} ; after ${rmem_post_netns[2]}"
			test_cleanup
		fi
	else
		test_cleanup
	fi
   fi
   printf "Results sender (${units}): "
   for (( i=0; i < ${#sbaseline_results[@]}; i++ ))
   do
	if [[ ${sbaseline_results[$i]} -gt ${stest_results[$i]} ]]; then  
		bold "Warning: baseline ${sbaseline_results[$i]} > test (${stest_results[$i]})"
	else
		echo "baseline (${sbaseline_results[$i]}) < test (${stest_results[$i]})"
	fi
   done
   printf "Results receiver (${units}): "
   for (( i=0; i < ${#rbaseline_results[@]}; i++ ))
   do
	if [[ ${rbaseline_results[$i]} -gt ${rtest_results[$i]} ]]; then
                bold "Warning: baseline ${rbaseline_results[$i]} > test (${rtest_results[$i]})"
	else
		echo "baseline (${rbaseline_results[$i]}) < test (${rtest_results[$i]})"
	fi      
   done 


   test_pass

   test_cleanup
 done
done

test_exit
