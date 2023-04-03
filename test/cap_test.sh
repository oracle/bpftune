#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# verify caps are dropped by bpftune after init

. ./test_lib.sh


SLEEPTIME=1

LOGFILE=$TESTLOG_LAST
OPTIONS="-ds"

test_start "$0|cap test: are caps dropped by bpftune after init?"

test_setup "true"

test_run_cmd_local "$BPFTUNE $OPTIONS &" true

sleep $SETUPTIME

caps=$(getpcaps $(pgrep bpftune) 2>&1 )

echo "caps: $caps"

if [[ "$caps" =~ "cap_sys_admin+p" ]]; then
	test_pass
fi
test_cleanup

test_exit
