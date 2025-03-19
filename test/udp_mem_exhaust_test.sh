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

SLEEPTIME=5
TIMEOUT=30
MAX_CONN=10

for FAMILY in ipv4 ipv6 ; do

   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|udp mem test to $ADDR:$PORT $FAMILY $MAX_CONN conn"

   rmem_default_orig=$(sysctl -n net.core.rmem_default)
   sysctl -w net.core.rmem_default=8192
   #rmem_max_orig=$(sysctl -n net.core.rmem_max)
   #sysctl -w net.core.rmem_max=8192
   mem_orig=($(sysctl -n net.ipv4.udp_mem))

   mem_test=($(echo 10 20 20))

   sysctl -w net.ipv4.udp_mem="${mem_test[0]} ${mem_test[1]} ${mem_test[2]}"

   test_setup true

   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -a udp_buffer_tuner.so -s &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
	fi
	set +e
	$IPERF3 -u -b100m -fm -P $MAX_CONN -p $PORT -c $ADDR
	set -e

	sleep $SLEEPTIME
   done

   mem_post=($(sysctl -n net.ipv4.udp_mem))
   rmem_max_post=$(sysctl -n net.core.rmem_max)
   sysctl -w net.ipv4.udp_mem="${mem_orig[0]} ${mem_orig[1]} ${mem_orig[2]}"
   #sysctl -w net.core.rmem_max=${rmem_max_orig}
   sysctl -w net.core.rmem_default=${rmem_default_orig}
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
