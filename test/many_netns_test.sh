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

# run iperf3 test with low wmem max, ensure tuner increases it while
# there are many netns set up; ensure no fd leaks

PORT=5201

. ./test_lib.sh

SLEEPTIME=1
TIMEOUT=30

set +e
LSOF=$(which lsof 2>/dev/null)
if [[ -z "$LSOF" ]]; then
     echo "lsof not available, skipping..."
     exit 0
fi
set -e

for i in $(seq 1 1000); do
     ip netns add ${NETNS_PREFIX}-extra${i}
done


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

   test_start "$0|many netns test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   wmem_orig=($(sysctl -n net.ipv4.tcp_wmem))

   test_setup true

   wmem_orig_netns=($(ip netns exec $NETNS sysctl -n net.ipv4.tcp_wmem))

   sysctl -w net.ipv4.tcp_wmem="${wmem_orig[0]} ${wmem_orig[1]} ${wmem_orig[1]}"
   ip netns exec $NETNS sysctl -w net.ipv4.tcp_wmem="${wmem_orig_netns[0]} ${wmem_orig_netns[1]} ${wmem_orig_netns[1]}"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -s &" true
		sleep $SETUPTIME
		fds_orig=$($LSOF -p $(pgrep bpftune) 2>/dev/null|wc -l)
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

        fi
	sleep $SLEEPTIME
   done

   fds=$($LSOF -p $(pgrep bpftune) 2>/dev/null|wc -l)
   # if we have 20 more than the original number of fds open, likely a leak
   fdsX=${fds_orig}+20
   if [[ "$fds" -gt $fdsX ]]; then
        echo "bpftune has $fds open versus original $fds_orig; fd leak? files:"
        $LSOF -p $(pgrep bpftune)
        test_cleanup
   fi
   echo "found $fds fds open for bpftune"
   pkill -TERM bpftune

   wmem_post=($(sysctl -n net.ipv4.tcp_wmem))
   wmem_post_netns=($(ip netns exec $NETNS sysctl -n net.ipv4.tcp_wmem))
   sysctl -w net.ipv4.tcp_wmem="${wmem_orig[0]} ${wmem_orig[1]} ${wmem_orig[2]}"
   if [[ $MODE == "test" ]]; then
	if [[ "${wmem_post[2]}" -gt ${wmem_orig[1]} ]]; then
		echo "wmem before ${wmem_orig[1]} ; after ${wmem_post[2]}"

		if [[ "${wmem_post_netns[2]}" -gt ${wmem_orig_netns[1]} ]]; then
			echo "netns wmem before ${wmem_orig_netns[1]} ; after ${wmem_post_netns[2]}"
		else
			echo "netns wmem before ${wmem_orig_netns[1]} ; after ${wmem_post_netns[2]}"
			if [[ ${BPFTUNE_NETNS} -eq 0 ]]; then
				echo "bpftune does not support per-netns policy, skipping..."
			else
				test_cleanup
			fi
		fi
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

   test_pass

   test_cleanup
 done
done

test_exit
