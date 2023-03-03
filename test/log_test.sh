#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# run sysctl test

. ./test_lib.sh


SLEEPTIME=1

for TUNER in neigh_table ; do

 for MODE in debug info syslog; do

   LOGFILE=$TESTLOG_LAST
   if [[ $MODE == "debug" ]]; then
	OPTIONS="-ds"
   elif [[ $MODE == "syslog" ]]; then
	OPTIONS="-d"
	LOGFILE=/var/log/messages
   else
	OPTIONS="-s"
   fi

   test_start "$0|log test: does setting $MODE logging generate messages?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE $OPTIONS &" true

   sleep $SETUPTIME
   grep "bpftune works" $LOGFILE
   if [[ "$OPTIONS" == "-ds" ]]; then
	# should see multiple lines for debug
	LINES=$(wc -l $LOGFILE | awk '{ print $1 }')
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
