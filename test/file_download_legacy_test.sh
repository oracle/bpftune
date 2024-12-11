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

# download file via wget with various drop/latencies; bbr should
# be used when drops >= 2%

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=50

for DROP_PERCENT in 2 0; do
for LATENCY in "" "delay 100" ; do
for NS in nonglobal global; do
 for FAMILY in ipv4 ipv6 ; do
   
   case $FAMILY in
   ipv4)
	if [[ $NS == "global" ]]; then
   	   ADDR=$VETH2_IPV4
	else
	   ADDR=$VETH1_IPV4
	fi
	WGET_ARG=""
	WGET_ADDR=$ADDR
	HTTP_BIND_ADDR=""
	;;
   ipv6)
	pyversion=$(python3 --version | awk -F '.' '{ print $2 }')
	# http.server supports IPv6 for 3.8 and later.
	if [[ $pyversion -lt 8 ]]; then
		echo "IPv6 test needs python 3.8 or later, skipping"
		continue
	fi
	if [[ $NS == "global" ]]; then
	   ADDR=$VETH2_IPV6
	else
	   ADDR=$VETH1_IPV6
	fi
	WGET_ARG="-6"
	WGET_ADDR="[${ADDR}]"
	HTTP_BIND_ADDR="--bind $ADDR"
	;;
   esac

   test_start "$0|file legacy test to $ADDR:$PORT $FAMILY $NS drop $DROP_PERCENT $LATENCY"

   if [[ $DROP_PERCENT -gt 0 ]]; then
        DROP=$DROP_PERCENT
   fi

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
   mkdir -p $SERVERDIR
   dd if=/dev/zero of=${SERVERFILE} bs=$SERVERFILE_SIZE  count=1

   set +e
   FIREWALLD_PID=$(pgrep firewalld)
   set -e
   if [[ -n "$FIREWALLD_PID" ]]; then
      service firewalld stop
   fi
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -sL &" true
		sleep $SETUPTIME
	else
		LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
		LOGSZ=$(expr $LOGSZ + 1)
	fi
	pushd $SERVERDIR	
	test_run_cmd_local "$SERVER_PREFIX python3 -m http.server $HTTP_BIND_ADDR $PORT &" true
	sleep $SLEEPTIME
	$CLIENT_PREFIX wget $WGET_ARG http://${WGET_ADDR}:${PORT}/file
	popd
	rm -f ${SERVERFILE}.1
	if [[ $MODE != "baseline" ]]; then
	    pkill -TERM bpftune
	    sleep $SETUPTIME
	    tail -n +${LOGSZ} $LOGFILE | grep bbr
	else
	    sleep $SLEEPTIME
	fi
   done
   if [[ -n "$FIREWALLD_PID" ]]; then
      service firewalld start
   fi
   test_pass	
   test_cleanup
 done
done
done
done

test_exit
