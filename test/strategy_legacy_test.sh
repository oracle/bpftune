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

# run sysctl test

. ./test_lib.sh


SLEEPTIME=10


test_start "$0|strategy legacy test: does strategy tuner appear, trigger event and change strategies?"

test_setup "true"

sleep 1
test_run_cmd_local "$BPFTUNE -dsLl ./strategy &" true
sleep $SETUPTIME
# trigger event
sysctl kernel.core_pattern
sleep $SLEEPTIME
grep -E "event .* for tuner strategy, strategy strategy_A" $TESTLOG_LAST
sleep 30
# trigger event
sysctl kernel.core_pattern
sleep $SLEEPTIME
grep -E "event .* for tuner strategy, strategy strategy_B" $TESTLOG_LAST
test_pass
test_cleanup
test_exit
