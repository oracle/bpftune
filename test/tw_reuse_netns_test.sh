#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2026, Oracle and/or its affiliates.

PORT=5201
CONN_COUNT=${CONN_COUNT:-128}
PORT_MIN=40000
PORT_MAX=$((PORT_MIN + CONN_COUNT - 1))

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST
TIMEOUT=90
SLEEPTIME=1

test_start "$0|tcp_tw_reuse test with $CONN_COUNT outbound connections and $CONN_COUNT ephemeral ports"

test_setup true

ip netns exec $NETNS sysctl -qw net.ipv4.tcp_tw_reuse=0
ip netns exec $NETNS sysctl -qw net.ipv4.tcp_timestamps=1
ip netns exec $NETNS sysctl -qw net.ipv4.ip_local_port_range="$PORT_MIN $PORT_MAX"

test_run_cmd_local "./conn_bomb -l $VETH2_IPV4 -p $PORT -b $CONN_COUNT -C $CONN_COUNT -c 1 -m twreuse -q -t $TIMEOUT &" true
sleep $SLEEPTIME
test_run_cmd_local "$BPFTUNE -da tcp_conn_tuner.so -s &" true
sleep $SETUPTIME

set +e
test_run_cmd_local "ip netns exec $NETNS ./conn_bomb -r $VETH2_IPV4 -P $PORT -C $CONN_COUNT -c 1 -m twreuse -q -t $TIMEOUT" true
set -e

sleep $SETUPTIME
tw_reuse_post=$(ip netns exec $NETNS sysctl -n net.ipv4.tcp_tw_reuse)
pkill -TERM bpftune || true
# ensures timewait sockets expire for next test
sleep $SLEEPTIME

grep "tcp_tw_reuse" $LOGFILE

if [[ "$tw_reuse_post" -ne 1 ]]; then
	echo "expected net.ipv4.tcp_tw_reuse to be 1, is $tw_reuse_post"
	test_cleanup
fi

test_pass
test_cleanup

test_exit
