#!/usr/bin/bash
#
# Copyright (c) 2022, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# run iperf3 test

PORT=5201

. ./test_lib.sh

SLEEPTIME=0.5
TIMEOUT=30

for FAMILY in ipv4 ipv6 ; do

for DROP_PERCENT in 10 0 ; do

 for CLIENT_OPTS in "" "-R" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|iperf3 test (drop $DROP_PERCENT %) to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   if [[ $DROP_PERCENT -gt 0 ]]; then
	DROP=$DROP_PERCENT
   fi

   test_setup "true"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -p $PORT -s -1 -D"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE &"
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		#LOGSZ=$(expr $LOGSZ + 1)
	fi
	sleep $SLEEPTIME
	set +e
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -p $PORT -c $ADDR" true
	set -e
	sleep $SLEEPTIME
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
		if [[ -z "$CLIENT_OPTS" ]]; then
			if [[ $DROP_PERCENT -gt 0 ]]; then
				tail -n +${LOGSZ} $LOGFILE | grep 'bbr'
			fi
		fi
        fi
	sleep $SLEEPTIME
   done

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
done

test_exit
