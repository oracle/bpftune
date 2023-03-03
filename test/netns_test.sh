#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.

# run sysctl test

. ./test_lib.sh


SLEEPTIME=2


test_start "$0|netns test: does adding/removing netns generate event?"

test_setup "true"

test_run_cmd_local "$BPFTUNE -ds &" true

if [[ ${BPFTUNE_NETNS} -eq 0 ]]; then
	echo "bpftune does not support per-netns policy, skipping..."
	test_pass
else
	sleep $SETUPTIME
	ip netns add testns.$$
	ip netns del testns.$$
	sleep $SLEEPTIME
	grep "netns created" $TESTLOG_LAST
	have_destroy=$(cat /proc/kallsyms |awk '$3 ~ /^net_free$/{ print $3}')
	# net_free() not present on some platforms
	if [[ -n "$have_destroy" ]]; then
		grep "netns destroyed" $TESTLOG_LAST
	fi
	test_pass
fi
test_cleanup
test_exit
