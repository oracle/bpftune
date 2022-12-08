#!/usr/bin/bash
#
# Copyright (c) 2022, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

# run sysctl test

. ./test_lib.sh


SLEEPTIME=0.5

for TUNER in neigh_table ; do

   test_start "$0|sysctl test: does setting sysctl switch off tuner?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SLEEPTIME
   for SYSCTL in kernel.core_pattern net.ipv4.neigh.default.gc_thresh1 ; do
	val=$(sysctl -qn $SYSCTL)
	sysctl -qw ${SYSCTL}=${val}
   done
   sleep $SLEEPTIME
   grep "modified sysctl" $TESTLOG_LAST
   test_pass

   test_cleanup
done

test_exit
