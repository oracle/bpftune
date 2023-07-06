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

# run service test

. ./test_lib.sh


SLEEPTIME=1


LOGFILE=$SYSLOGFILE

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

test_start "$0|service test: does enabling the service work?"
test_run_cmd_local "systemctl enable bpftune"
sleep $SETUPTIME
test_pass

test_start "$0|service test: does disabling the service work?"
test_run_cmd_local "systemctl disable bpftune"
sleep $SETUPTIME
test_pass

test_cleanup

test_exit
