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

 for OPTIONS in "-ds" "-s" ; do
   test_start "$0|log test: does setting $OPTIONS generate messages?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE $OPTIONS &" true

   sleep $SLEEPTIME
   for SYSCTL in kernel.core_pattern net.ipv4.neigh.default.gc_thresh1 ; do
	val=$(sysctl -qn $SYSCTL)
	sysctl -qw ${SYSCTL}=${val}
   done
   grep "modified sysctl" $TESTLOG_LAST
   if [[ "$OPTIONS" == "-ds" ]]; then
	# should see multiple lines for debug
	LINES=$(wc -l $TESTLOG_LAST | awk '{ print $1 }')
	if [[ $LINES -gt 1 ]]; then
	   test_pass
	fi
   else
	test_pass
   fi

   test_cleanup
 done
done

test_exit
