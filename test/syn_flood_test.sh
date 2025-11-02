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

# check performance under syn flood

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=50

for NS in nonglobal global ; do
 for FAMILY in ipv4 ; do
   
   case $FAMILY in
   ipv4)
	if [[ $NS == "global" ]]; then
   	   ADDR=$VETH2_IPV4
	else
	   ADDR=$VETH1_IPV4
	fi
	DUMMY_SERVER=192.168.200.3
	DUMMY_CLIENT=192.168.200.4
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
	DUMMY_SERVER=fe::1
	DUMMY_CLIENT=fe::2
	WGET_ARG="-6"
	WGET_ADDR="[${ADDR}]"
	HTTP_BIND_ADDR="--bind $ADDR"
	;;
   esac

   test_start "$0|syn flood test to $ADDR:$PORT $FAMILY $NS "

   if [[ $NS == "global" ]]; then
	 CLIENT_PREFIX="ip netns exec $NETNS"
	 CLIENT_VETH=$VETH1
	 export SERVER_PREFIX=""
	 SERVER_VETH=$VETH2
   else
	 CLIENT_PREFIX=""
	 CLIENT_VETH=$VETH2
	 export SERVER_PREFIX="ip netns exec $NETNS"
	 SERVER_VETH=$VETH1
   fi
   test_setup true
   syn_backlog_pre=256
   $SERVER_PREFIX sysctl -w net.ipv4.tcp_max_syn_backlog=$syn_backlog_pre
   $SERVER_PREFIX sysctl -w net.ipv4.tcp_syncookies=0

   mkdir -p $SERVERDIR

   set +e
   FIREWALLD_PID=$(pgrep firewalld)
   set -e
   if [[ -n "$FIREWALLD_PID" ]]; then
      service_cmd stop firewalld
   fi
   pushd $SERVERDIR
   test_run_cmd_local "$SERVER_PREFIX python3 -m http.server $PORT &" true
   popd
   sleep $SLEEPTIME

   set +e
   $SERVER_PREFIX ip link add dummyserver type dummy
   $SERVER_PREFIX ip addr add ${DUMMY_SERVER}/24 dev dummyserver
   $SERVER_PREFIX ip link set dummyserver up
   $SERVER_PREFIX ip link set dummyserver arp on
   $SERVER_PREFIX ip link set lo up
   set -e

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
	$SERVER_PREFIX $HPING -a $DUMMY_CLIENT -S -i u1 -c 1000000 -S -p $PORT $DUMMY_SERVER
	set -e
	if [[ $MODE != "baseline" ]]; then
	    pkill -TERM bpftune
	    sleep $SETUPTIME
	    tail -n +${LOGSZ} $LOGFILE
	else
	    sleep $SLEEPTIME
	fi
   done
   if [[ -n "$FIREWALLD_PID" ]]; then
      service_cmd start firewalld
   fi
   $SERVER_PREFIX ip link del dummyserver

   syn_backlog_post=$($SERVER_PREFIX sysctl -n net.ipv4.tcp_max_syn_backlog)
   if [[ $syn_backlog_post -ge $syn_backlog_pre ]]; then
	   echo "net.ipv4.tcp_max_syn_backlog unexpectedly increased to $syn_backlog_post"
   else
	   test_pass
   fi
   test_cleanup
 done
done

test_exit
