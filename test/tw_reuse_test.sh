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

restore_tw_reuse_sysctls()
{
	set +e
	if [[ ${#port_range_orig[@]} -eq 2 ]]; then
		sysctl -qw net.ipv4.ip_local_port_range="${port_range_orig[0]} ${port_range_orig[1]}"
	fi
	if [[ -n "${tw_reuse_orig:-}" ]]; then
		sysctl -qw net.ipv4.tcp_tw_reuse=$tw_reuse_orig
	fi
	if [[ -n "${timestamps_orig:-}" ]]; then
		sysctl -qw net.ipv4.tcp_timestamps=$timestamps_orig
	fi
	set -e
}

tw_reuse_cleanup_exit()
{
	restore_tw_reuse_sysctls
	test_cleanup_exit
}

test_start "$0|tcp_tw_reuse test with $CONN_COUNT outbound connections and $CONN_COUNT ephemeral ports"

tw_reuse_orig=$(sysctl -n net.ipv4.tcp_tw_reuse)
timestamps_orig=$(sysctl -n net.ipv4.tcp_timestamps)
port_range_orig=($(sysctl -n net.ipv4.ip_local_port_range))

test_setup true
trap tw_reuse_cleanup_exit EXIT

sysctl -qw net.ipv4.tcp_tw_reuse=0
sysctl -qw net.ipv4.tcp_timestamps=1
sysctl -qw net.ipv4.ip_local_port_range="$PORT_MIN $PORT_MAX"

test_run_cmd_local "ip netns exec $NETNS ./conn_bomb -l $VETH1_IPV4 -p $PORT -b $CONN_COUNT -C $CONN_COUNT -c 1 -m twreuse -q -t $TIMEOUT &" true
sleep $SLEEPTIME
test_run_cmd_local "$BPFTUNE -da tcp_conn_tuner.so -s &" true
sleep $SETUPTIME

set +e
test_run_cmd_local "./conn_bomb -r $VETH1_IPV4 -P $PORT -C $CONN_COUNT -c 1 -m twreuse -q -t $TIMEOUT" true
set -e

sleep $SETUPTIME
tw_reuse_post=$(sysctl -n net.ipv4.tcp_tw_reuse)
pkill -TERM bpftune || true
# ensures timewait sockets expire for next test
sleep 60

grep "tcp_tw_reuse" $LOGFILE

if [[ "$tw_reuse_post" -ne 1 ]]; then
	echo "expected net.ipv4.tcp_tw_reuse to be 1, is $tw_reuse_post"
	test_cleanup
fi

restore_tw_reuse_sysctls
test_pass
test_cleanup

test_exit
