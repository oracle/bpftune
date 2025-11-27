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

# run iperf3 test with low netdev_budget, ensure tuner increases it.

PORT=5201

. ./test_lib.sh

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=100

for FAMILY in ipv4 ipv6 ; do

 for CLIENT_OPTS in "" ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH2_IPV4
	;;
   ipv6)
	ADDR=$VETH2_IPV6
	;;
   esac

   test_start "$0|budget test to $ADDR:$PORT $FAMILY opts $CLIENT_OPTS $LATENCY"

   budget_orig=($(sysctl -n net.core.netdev_budget))
   usecs_orig=($(sysctl -n net.core.netdev_budget_usecs))
   test_setup true

   sysctl -w net.core.netdev_budget=5
   sysctl -w net.core.netdev_budget_usecs=8000
   sysctl -w net.core.netdev_budget_usecs=2000
   budget_pre=($(sysctl -n net.core.netdev_budget))
   usecs_pre=($(sysctl -n net.core.netdev_budget_usecs))
   declare -A results
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "$IPERF3 -s -p $PORT &"
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -s &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -fm -t 10 $CLIENT_OPTS -c $PORT -c $ADDR" true
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

   budget_post=($(sysctl -n net.core.netdev_budget))
   usecs_post=($(sysctl -n net.core.netdev_budget_usecs))
   sleep $SLEEPTIME
   sysctl -w net.core.netdev_budget="$budget_orig"
   sysctl -w net.core.netdev_budget_usecs="$usecs_orig"
   echo "budget	${budget_pre}	->	${budget_post}"
   echo "usecs	${usecs_pre}	->	${usecs_post}"
   test_pass
   test_cleanup
 done
done

test_exit
