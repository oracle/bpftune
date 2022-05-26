#!/usr/bin/bash
#
# Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# Setup/teardown code for testing.

export TESTDIR="/tmp/bpftunetest"
export TESTLOG=${TESTLOG:-"${TESTDIR}/testlog.${PPID}"}
export TESTLOG_LAST="${TESTDIR}/testlog.last"

export PASSED=${PASSED:-0}

# 1: more output, >1: xtrace
export VERBOSE=${VERBOSE:-0}
# Set the following to 1 if you want to see state after failure.
export SKIP_CLEANUP=${SKIP_CLEANUP:-0}

check_prog()
{
	PROGNAME=$1
	PKGNAME=$2

	if [ -z "$PROGNAME" ]; then
		echo "no '$PROGNAME'; install $PKGNAME"
		exit 1
	fi
}

export NC=$(which nc 2>/dev/null)
check_prog nc nmap-ncat
export IPERF3=$(which iperf3 2>/dev/null)
check_prog iperf3 iperf3
export QPERF=$(which qperf 2>/dev/null)
check_prog qperf qperf
export FIREWALL_CMD=$(which firewall-cmd 2>/dev/null)

export B=$(tput -Tvt100 bold)
export N=$(tput -Tvt100 sgr0)

test_init()
{
	if [ $VERBOSE -gt 1 ]; then
		set -o xtrace
		export bpfevent_debug=1
	fi
	set -o nounset
	set -o errexit

	mkdir -p $TESTDIR
}

export CMD_PIDFILE="${TESTDIR}/.current_test_cmd.pid"

export BANDWIDTH=${BANDWIDTH:-"0"}

export TIMEOUT=${TIMEOUT:-"30"}

export TEST_INFO="No test running yet"
export NUM_TESTS=0

export TARGET=127.0.0.1

export PORT=${PORT:-10200}
export NETNS_PREFIX="bpftunens"
export NETNS="${NETNS_PREFIX}-$$"
export VETH1="veth1-$$"
export VETH1_IPV4="192.168.168.1"
export VETH1_IPV6="fd::1"
export VETH2="veth2-$$"
export VETH2_IPV4="192.168.168.2"
export VETH2_IPV6="fd::2"
export MTU=1500
export DROP=${DROP:-""}
export LATENCY=${LATENCY:-""}

export BPFTUNE=../src/bpftune
export CGROUPDIR=${CGROUPDIR:-"/tmp/cgroupv2"}
export BPFTUNE="../src/bpftune -c $CGROUPDIR"

# Don't want __pycache__ files hanging around.
export PYTHONCMD="python3 -B"

export EXITCODE=1

bold()
{
	echo "${B}$1${N}"
}

test_run_cmd_local()
{
	CMDLOG="${TESTDIR}/testlog.$$"
	CMD="$1"
	DO_REDIRECT=${2:-"false"}

	if [[ $VERBOSE -gt 0 ]]; then
		echo "Running \"$CMD\" on $(uname -n)."
	fi

	if [[ "$DO_REDIRECT" == "true" ]]; then
		rm -f $TESTLOG_LAST
		touch $CMDLOG
		ln -s $CMDLOG $TESTLOG_LAST
		if [[ $VERBOSE -gt 0 ]]; then
			echo "For output see ${CMDLOG}"
		fi
        fi

	BGCMD="&"
	if [[ "$CMD" =~ $BGCMD ]]; then
		NOBGCMD="$(echo $CMD | sed 's/&//g')"
		if [[ $DO_REDIRECT == "true" ]]; then
			( $NOBGCMD >>$CMDLOG 2>&1 </dev/null  ) &
		else
			( $NOBGCMD >>/dev/null 2>&1 </dev/null ) &
		fi
		CMD_PID=$!
		echo $CMD_PID >> $CMD_PIDFILE
	else
		if [[ $DO_REDIRECT == "true" ]]; then
			timeout $TIMEOUT $CMD >>$CMDLOG 2>&1
		else
			timeout $TIMEOUT $CMD
		fi
	fi
}

test_setup_local()
{
	CMD=$1
	TIMEOUT=$2

	if [[ ! -d $CGROUPDIR ]]; then
		mkdir -p $CGROUPDIR
	fi
	set +e
	MOUNTED=$(mount | grep $CGROUPDIR)
	set -e
	if [[ -z "$MOUNTED" ]]; then
		mount -t cgroup2 none $CGROUPDIR
	fi
	# test_setup_local() can be called multiple times for a test...
	set +e
	ip netns list 2>/dev/null | grep $NETNS
	FOUND=$?
	set -e
	if [[ $FOUND -ne 0 ]]; then
		ip netns pids $NETNS 2>/dev/null| xargs -r kill
		ip netns del $NETNS 2>/dev/null|true
		sleep 0.2
		ip netns add $NETNS
		ip link add dev $VETH1 mtu $MTU netns $NETNS type veth \
		   peer name $VETH2 mtu $MTU
		ip netns exec $NETNS ip addr add ${VETH1_IPV4}/24 dev $VETH1
		ip netns exec $NETNS ip -6 addr add ${VETH1_IPV6}/64 dev $VETH1
		ip netns exec $NETNS ip link set $VETH1 up
		ip netns exec $NETNS sysctl -qw net.ipv4.conf.lo.rp_filter=0
		if [[ -n "$DROP" ]] || [[ -n "$LATENCY" ]]; then
		 D=$DROP
		 if [[ -n "$DROP" ]]; then
		  D="${DROP}%"
		 fi
       	         tc qdisc add dev $VETH2 root netem loss ${D} ${LATENCY}
		 ethtool -K $VETH2 gso off
        	fi
		ip addr add ${VETH2_IPV4}/24 dev $VETH2
		ip -6 addr add ${VETH2_IPV6}/64 dev $VETH2
		ip link set $VETH2 up
		sleep 0.2
		ping -c 3 $VETH2_IPV4 >/dev/null 2>&1

	else
		echo "skipping netns setup, $NETNS already present"
	fi
	if [[ -f "$FIREWALL_CMD" ]]; then
		$FIREWALL_CMD --add-port=${PORT}/tcp
	fi
	test_run_cmd_local "$CMD" true
}

test_cleanup_local()
{
	EXIT=$1

	sleep 0.2
	if [ -f "$CMD_PIDFILE" ]; then
		CMD_PIDS=`cat $CMD_PIDFILE`
		for CMD_PID in $CMD_PIDS ; do
			kill -TERM $CMD_PID >/dev/null 2>&1 || true
		done
		rm -f $CMD_PIDFILE
	fi

	ip --all netns del ${NETNS_PREFIX}\*

	if [[ $EXIT -ne 0 ]]; then
		if [[ -f $TESTLOG_LAST ]]; then
			echo "Output of last command:"
			cat $TESTLOG_LAST
		fi
	else
		# Clear log for next test
		echo "" > $TESTLOG_LAST
	fi
}

test_log_result()
{
	if [ $EXITCODE -ne 0 ]; then
		RESULT="FAIL; error $EXITCODE|"
	else
		RESULT="PASS($PASSED)"
	fi
	NUM_TESTS=`expr $NUM_TESTS + 1`

	bold "$TEST_INFO|$RESULT"
	bold "$TEST_INFO|$RESULT" >> $TESTLOG
}

test_exit()
{
	exit $EXITCODE
}

test_cleanup()
{
	trap - EXIT

	test_cleanup_local $EXITCODE
	if [ $EXITCODE -ne 0 ]; then
		test_log_result
		exit 1
	fi
}

test_cleanup_exit()
{
	if [[ $SKIP_CLEANUP -ne 0 ]]; then
		echo "skipping cleanup as requested"
		if [ $EXITCODE -ne 0 ]; then
			test_log_result
		fi
	else
		test_cleanup
	fi
	test_exit
}

test_setup()
{
	CMD="$1"

	if [ "$(id -u)" != "0" ]; then
		echo "Sorry, tests must run as root"
		exit 1
	fi
	mkdir -p $TESTDIR

	trap test_cleanup_exit EXIT

	test_setup_local "$CMD" $TIMEOUT
}

test_start()
{
	TEST_INFO=$1

	bold "$TEST_INFO|START"
	bold "$TEST_INFO|START" >> $TESTLOG
	# Tests fail by default; need explicit test_pass
	EXITCODE=1
}

test_log_info()
{
	INFO=$1

	echo $1
	echo $1 >> $TESTLOG
}

test_pass()
{
	EXITCODE=0
	PASSED=$(expr $PASSED + 1)
	test_log_result
}

test_end()
{
	if [ $EXITCODE -ne 0 ]; then
		test_cleanup_exit
	fi
}

test_init
