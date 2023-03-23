#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.

# run sysctl test

. ./test_lib.sh


SLEEPTIME=5


test_start "$0|sample legacy test: does sample tuner appear, trigger event and disappear?"

test_setup "true"

test_run_cmd_local "$BPFTUNE -dsL &" true
sleep $SETUPTIME
cd ../sample_tuner ; make install
sleep $SLEEPTIME
# trigger event
sysctl kernel.core_pattern
sleep $SLEEPTIME
grep -E "event .* for tuner sample" $TESTLOG_LAST
# remove tuner
rm /usr/local/lib64/bpftune/sample_tuner.so
sleep $SLEEPTIME
grep "fini tuner sample" $TESTLOG_LAST
test_pass
test_cleanup
test_exit
