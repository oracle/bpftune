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

# run qperf test

TUNER=${TUNER:-}
if [[ -n "$TUNER" ]]; then
	BPFTUNE_FLAGS="$BPFTUNE_FLAGS -a $TUNER"
fi

. ./test_lib.sh

set +e
$QPERF -h >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
	echo "$QPERF does not work, skipping qperf-based tests..."
	exit 0
fi
set -e
LOGFILE=$TESTLOG_LAST

for FAMILY in ipv4 ipv6 ; do

SLEEPTIME=0.5

DROP=0

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
		test_run_cmd_local "$BPFTUNE -s &" true
		sleep $SETUPTIME
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

   echo "Following changes were made:"
   set +e
   grep "bpftune" $LOGFILE
   set -e

   test_pass

   test_cleanup
 done
 done
done

test_exit
