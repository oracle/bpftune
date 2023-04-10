#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# run sysctl test

. ./test_lib.sh


SLEEPTIME=1

for MODE in debug info syslog service; do

   LOGFILE=$TESTLOG_LAST
   case $MODE in
   debug)
	OPTIONS="-ds"
	BPFTUNECMD="$BPFTUNE $OPTIONS &"
	;;
   syslog)
	OPTIONS="-d"
	BPFTUNECMD="$BPFTUNE $OPTIONS &"
	LOGFILE=/var/log/messages
	;;
   service)
	BPFTUNECMD="service bpftue start"
	LOGFILE=/var/log/messages
	;;
   *)
	OPTIONS="-s"
	BPFTUNECMD="$BPFTUNE $OPTIONS &"
	;;
   esac

   test_start "$0|log test: does setting $MODE logging generate messages for $BPFTUNECMD?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNECMD &" true

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

test_exit
