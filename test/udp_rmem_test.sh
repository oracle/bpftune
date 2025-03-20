#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2025, Oracle and/or its affiliates.
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
MAX_CONN=1

# udp_fail_queue_rcv_skb tracepoint IPv6 support only on 6.4+ kernels.
FAMILIES="ipv4"
if [[ $MAJ_KVER -ge 6 ]]; then
	if [[ $MIN_KVER -ge 4 ]]; then
		FAMILIES="$FAMILIES ipv6"
	fi
fi

for FAMILY in $FAMILIES ; do
 for BW in 500m 1000m 5000m 10000m ; do
   case $FAMILY in
   ipv4)
   	ADDR=$VETH1_IPV4
	;;
   ipv6)
	ADDR=$VETH1_IPV6
	;;
   esac

   test_start "$0|udp rmem test $BW to $ADDR:$PORT $FAMILY $MAX_CONN conn"

   rmem_default_orig=$(sysctl -n net.core.rmem_default)
   rmem_max_orig=$(sysctl -n net.core.rmem_default)
   rmem_test=16384
   sysctl -w net.core.rmem_default=$rmem_test
   sysctl -w net.core.rmem_max=$rmem_test

   test_setup true

   declare -A results
   for MODE in baseline baseline_with_bpftune test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "ip netns exec $NETNS $IPERF3 -s -p $PORT -1 &"
	if [[ $MODE == "baseline_with_bpftune" ]]; then
		test_run_cmd_local "$BPFTUNE -a udp_buffer_tuner.so -s &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
	fi
	set +e
	test_run_cmd_local "$IPERF3 -u -b${BW} -fm -P $MAX_CONN -p $PORT -c $ADDR " true
	IPERF_STATUS=$?
        set -e
        sresults=$(grep -E "sender" ${CMDLOG} | awk '{print $7}')
        rresults=$(grep -E "receiver" ${CMDLOG} | awk '{print $7}')
        units=$(grep -E "sender|receiver" ${CMDLOG} | awk '{print $8}' |head -1)

        if [[ $MODE == "baseline" ]]; then
                read -r -a sbaseline_results <<< $sresults
                read -r -a rbaseline_results <<< $rresults
                echo "" > ${CMDLOG}
	elif [[ $MODE == "baseline_with_bpftune" ]]; then
		read -r -a sbbaseline_results <<< $sresults
                read -r -a rbbaseline_results <<< $rresults
	elif [[ $MODE == "test" ]]; then
                read -r -a stest_results <<< $sresults
                read -r -a rtest_results <<< $rresults
        fi
	sleep $SLEEPTIME
   done
   $BPFTUNE_PROG -q summary
   pkill -TERM bpftune
   sleep $SETUPTIME


   if [[ $IPERF_STATUS == 0 ]]; then
   printf "Results sender (${units}): "
   for (( i=0; i < ${#sbaseline_results[@]}; i++ ))
   do
        sbase=$(roundup ${sbaseline_results[$i]})
	sbbase=$(roundup ${sbbaseline_results[$i]})
        stest=$(roundup ${stest_results[$i]})
        if [[ ${sbase} -gt ${stest} ]]; then
                bold "Warning: baseline (${sbase}) > test (${stest})"
	elif [[ ${sbbase} -gt ${stest} ]]; then
		bold "Warning: baseline_with_bpftune (${sbbase}) > test (${stest})"
	else
		echo "baseline (${sbase}) <= baseline_with_bpftune (${sbbase}) <= test (${stest})"
        fi
   done
   printf "Results receiver (${units}): "
   for (( i=0; i < ${#rbaseline_results[@]}; i++ ))
   do
        rbase=$(roundup ${rbaseline_results[$i]})
	rbbase=$(roundup ${rbbaseline_results[$i]})
        rtest=$(roundup ${rtest_results[$i]})
        if [[ ${rbase} -gt ${rtest} ]]; then
                bold "Warning: baseline (${rbase}) > test (${rtest})"
	elif [[ ${rbbase} -gt ${rtest} ]]; then
		bold "Warning: baseline_with_bpftune (${rbbase}) > test (${rtest})"
        else
		echo "baseline (${rbase}) <= baseline_with_bpftune (${rbbase}) <= test (${rtest})"
        fi
   done
   fi

   rmem_default_post=($(sysctl -n net.core.rmem_default))
   rmem_max_post=$(sysctl -n net.core.rmem_max)
   sysctl -w net.core.rmem_default=$rmem_default_orig
   sysctl -w net.core.rmem_max=${rmem_max_orig}
   echo "mem before rmem default, max ${rmem_test} ${rmem_test}"
   echo "mem after $rmem_default_post $rmem_max_post"
   if [[ $MODE == "test" ]]; then
	echo "Following changes were made:"
	set +e
	grep bpftune $LOGFILE
	set -e
	if [[ "$rmem_max_post" -gt ${rmem_test} ]]; then
		if [[ "$rmem_default_post" -gt ${rmem_test} ]]; then
			test_pass
		fi
	fi
   fi

   test_cleanup
 done
done

test_exit
