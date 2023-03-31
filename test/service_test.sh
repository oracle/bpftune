#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# run service test

. ./test_lib.sh


SLEEPTIME=1


LOGFILE=/var/log/messages

test_start "$0|service test: does enabling/disabling the service work?"

test_setup "true"

test_run_cmd_local "service bpftune start" true

sleep $SETUPTIME
grep "bpftune works" $LOGFILE
pgrep bpftune

test_run_cmd_local "service bpftune stop" true
sleep $SETUPTIME
test_pass
test_cleanup

test_exit
