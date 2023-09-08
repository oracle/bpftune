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

# run iperf3 test with low wmem max, ensure tuner increases it but it is
# rolled back on exit.

PORT=5201

. ./test_lib.sh

SLEEPTIME=1
TIMEOUT=30

for FAMILY in ipv4 ipv6 ; do

 for CLIENT_OPTS in "" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|rollback legacy test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   wmem_orig=($(sysctl -n net.ipv4.tcp_wmem))

   test_setup true

   sysctl -w net.ipv4.tcp_wmem="${wmem_orig[0]} ${wmem_orig[1]} ${wmem_orig[1]}"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -LR &"
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -p $PORT -c $ADDR" true

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
		pkill -TERM bpftune
		sleep $SETUPTIME
        fi
	sleep $SLEEPTIME
   done

   wmem_post=($(sysctl -n net.ipv4.tcp_wmem))
   sysctl -w net.ipv4.tcp_wmem="${wmem_orig[0]} ${wmem_orig[1]} ${wmem_orig[2]}"
   if [[ $MODE == "test" ]]; then
	if [[ "${wmem_post[2]}" -eq ${wmem_orig[1]} ]]; then
		echo "wmem before ${wmem_orig[1]} ; after ${wmem_post[2]}"
	else
		test_cleanup
	fi
   fi
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

   grep "Rolling back" $LOGFILE

   test_pass

   test_cleanup
 done
done

test_exit
