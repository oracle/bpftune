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

if [[ ${BPFTUNE_NETNS} -eq 0 ]]; then
	echo "bpftune does not support per-netns policy, skipping..."
	test_pass
else
	test_run_cmd_local "$BPFTUNE -dsL &" true
	sleep $SETUPTIME
	ip netns add testns.$$
	ip netns del testns.$$
	sleep $SLEEPTIME
	grep "netns created" $TESTLOG_LAST
	test_pass
fi
test_cleanup
test_exit
