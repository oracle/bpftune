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

test_start "$0|service test: does enabling the service work?"

test_setup "true"

test_run_cmd_local "service bpftune start" true

sleep $SETUPTIME
grep "bpftune works" $LOGFILE
oldpid=$(pgrep bpftune)

test_pass

test_start "$0|service test: does restarting the service work?"

test_run_cmd_local "service bpftune restart"

sleep $SETUPTIME
newpid=$(pgrep bpftune)

if [[ "$newpid" -ne "$oldpid" ]]; then
	test_pass
else
	test_cleanup
fi

test_start "$0|service test: does stopping the service work?"
test_run_cmd_local "service bpftune stop" true
sleep $SETUPTIME

set +e
gonepid=$(pgrep bpftune)
set -e

if [[ -n "$gonepid" ]]; then
	echo "bpftune still running: $gonepid"
	test_cleanup
else
	test_pass
fi

test_cleanup

test_exit
