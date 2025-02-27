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

# run iperf3 test with low rmem max, ensure sampling was used
# on rcvbuf expand.

PORT=5201

. ./test_lib.sh

SLEEPTIME=1
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

   test_start "$0|rate test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   rmem_orig=($(sysctl -n net.ipv4.tcp_rmem))

   test_setup true

   rmem_orig_netns=($(ip netns exec $NETNS sysctl -n net.ipv4.tcp_rmem))

   sysctl -w net.ipv4.tcp_rmem="${rmem_orig[0]} ${rmem_orig[1]} ${rmem_orig[1]}"
   ip netns exec $NETNS sysctl -w net.ipv4.tcp_rmem="${rmem_orig_netns[0]} ${rmem_orig_netns[1]} ${rmem_orig_netns[1]}"

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -s &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -c $PORT -c $ADDR" true
	sleep $SLEEPTIME
   done

   pkill -TERM bpftune
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
   sleep $SLEEPTIME

   grep "Sample" $TESTLOG_LAST

   test_pass

   test_cleanup
 done
done

test_exit
