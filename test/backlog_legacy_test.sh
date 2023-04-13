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

# run iperf3 test with low netdev_max_backlog, ensure tuner increases it.

PORT=5201

. ./test_lib.sh

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=50

for FAMILY in ipv4 ipv6 ; do

 for CLIENT_OPTS in "-R -P $MAX_CONN" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|backlog legacy test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   backlog_orig=($(sysctl -n net.core.netdev_max_backlog))

   test_setup true

   sysctl -w net.core.netdev_max_backlog=4
   backlog_pre=($(sysctl -n net.core.netdev_max_backlog))
   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -l &"
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	test_run_cmd_local "$IPERF3 -fm $CLIENT_OPTS -c $PORT -c $ADDR" true
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

   backlog_post=($(sysctl -n net.core.netdev_max_backlog))
   sysctl -w net.core.netdev_max_backlog="$backlog_orig"
   if [[ $MODE == "test" ]]; then
	if [[ "${backlog_post}" -gt ${backlog_pre} ]]; then
		echo "backlog before ${backlog_pre} ; after ${backlog_post}"
	else
		test_cleanup
	fi
   fi

   test_pass

   test_cleanup
 done
done

test_exit
