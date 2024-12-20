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

# test various queries

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=50

test_setup true
for QUERY in help tuners tunables ; do
   test_start "$0|query $QUERY test"
   test_run_cmd_local "$BPFTUNE -s &" true
   sleep $SETUPTIME
   $BPFTUNE_CMD -q $QUERY
   test_pass
done
test_cleanup

for FAMILY in ipv4 ; do
 for NS in global; do
   case $FAMILY in
   ipv4)
	if [[ $NS == "global" ]]; then
   	   ADDR=$VETH2_IPV4
	else
	   ADDR=$VETH1_IPV4
	fi
	SYSCTL_PREFIX=net.ipv4.ipfrag_
	SYSCTL_NAME="${SYSCTL_PREFIX}high_thresh"
	;;
   ipv6)
	if [[ $NS == "global" ]]; then
	   ADDR=$VETH2_IPV6
	else
	   ADDR=$VETH1_IPV6
	fi
	SYSCTL_PREFIX=net.ipv6.ip6frag_
	SYSCTL_NAME="${SYSCTL_PREFIX}high_thresh"
	;;
   esac

   test_start "$0|query summary test to $ADDR:$PORT $FAMILY $NS"

   if [[ $NS == "global" ]]; then
	 CLIENT_PREFIX="ip netns exec $NETNS"
	 CLIENT_VETH=$VETH1
	 SERVER_PREFIX=""
	 SERVER_VETH=$VETH2
   else
	 CLIENT_PREFIX=""
	 CLIENT_VETH=$VETH2
	 SERVER_PREFIX="ip netns exec $NETNS"
	 SERVER_VETH=$VETH1
   fi
   test_setup true

   $CLIENT_PREFIX ethtool --offload $CLIENT_VETH rx off tx off gso off gro off lro off tso off
   $SERVER_PREFIX ethtool --offload $SERVER_VETH rx off tx off gso off gro off lro off tso off
   frag_orig=($(sysctl -n $SYSCTL_NAME))
   low_orig=($(sysctl -n ${SYSCTL_PREFIX}low_thresh))
   sysctl -w ${SYSCTL_PREFIX}low_thresh=8192
   sysctl -w $SYSCTL_NAME="8192"

   frag_pre=($(sysctl -n $SYSCTL_NAME))

   # prevent firewall from reassembling packets.
   set +e
   FIREWALLD_PID=$(pgrep firewalld)
   set -e
   if [[ -n "$FIREWALLD_PID" ]]; then
      service firewalld stop
   fi
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -s &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	set +e
	echo "Running $CLIENT_PREFIX ping -v -c 20 -M t -s 8192 $ADDR"
	$CLIENT_PREFIX ping -v -c 20 -M want -s 8192 $ADDR
	set -e

	sleep $SLEEPTIME
   done
   if [[ -n "$FIREWALLD_PID" ]]; then
      service firewalld start
   fi
   frag_post=($(sysctl -n $SYSCTL_NAME))
   if [[ -n $SERVER_PREFIX ]]; then
	   sysctl -w ${SYSCTL_NAME}=$frag_orig
	   sysctl -w ${SYSCTL_PREFIX}low_thresh=$low_orig
   fi
   echo "$SYSCTL_NAME before ${frag_pre}"
   echo "$SYSCTL_NAME after  ${frag_post}"
   if [[ $MODE == "test" ]]; then
	if [[ "${frag_post}" -gt ${frag_pre} ]]; then
		grep "approaching fragmentation maximum threshold" $LOGFILE
		${BPFTUNE_PROG} -q summary
		pkill -TERM bpftune
		test_pass
	else
		pkill -TERM bpftune
		test_cleanup
	fi
   fi

   test_cleanup
 done
done

test_exit
