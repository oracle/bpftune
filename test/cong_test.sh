#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates.
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

PORT=5201

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30

for FAMILY in ipv6 ipv4 ; do

for DROP_PERCENT in 0 10; do
 for LATENCY in "delay 100" ""; do
 for CLIENT_OPTS in "" "-R" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|cong test (drop $DROP_PERCENT %) to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   if [[ $DROP_PERCENT -gt 0 ]]; then
	DROP=$DROP_PERCENT
   fi

   test_setup "true"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -p $PORT -s &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -ds &" true
		sleep $SETUPTIME
		# warm up connection...
		for i in {1..40}; do
			set +e
			$IPERF3 -fm $CLIENT_OPTS -p $PORT -t 1 -c $ADDR > /dev/null 2>&1
			set -e
		done
	else
		sleep $SLEEPTIME
	fi
	set +e
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -p $PORT -c $ADDR" true
	IPERF_STATUS=$?
	set -e
	if [[ $MODE != "baseline" ]]; then
		pkill -TERM bpftune
		sleep $SETUPTIME
	fi
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

   if [[ $IPERF_STATUS == 0 ]]; then
   printf "Results sender (${units}): "
   for (( i=0; i < ${#sbaseline_results[@]}; i++ ))
   do
	sbase=$(roundup ${sbaseline_results[$i]})
	stest=$(roundup ${stest_results[$i]})
	if [[ ${sbase} -gt ${stest} ]]; then  
		bold "Warning: baseline (${sbase}) > test (${stest})"
	else
		echo "baseline (${sbase}) < test (${stest})"
	fi
   done
   printf "Results receiver (${units}): "
   for (( i=0; i < ${#rbaseline_results[@]}; i++ ))
   do
	rbase=$(roundup ${rbaseline_results[$i]})
        rtest=$(roundup ${rtest_results[$i]})
	if [[ ${rbase} -gt ${rtest} ]]; then
                bold "Warning: baseline (${rbase}) > test (${rtest})"
	else
		echo "baseline (${rbase}) < test (${rtest})"
	fi      
   done 
   fi
   sleep $SETUPTIME
   grep "Summary: tcp_conn_tuner" $LOGFILE

   test_pass

   test_cleanup
 done
 done
done
done

test_exit
