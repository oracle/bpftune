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

# run socket stress-ng test in baseline/test to compare differences
# in ops/sec

. ./test_lib.sh

LOGFILE=$TESTLOG_LAST

SLEEPTIME=1
TIMEOUT=30
MAX_CONN=500

for SOCKS in 10 $MAX_CONN ; do 
   test_start "$0|stress-ng test, $SOCKS sockets"

   test_setup true

   set +e
   FIREWALLD_PID=$(pgrep firewalld)
   set -e
   if [[ -n "$FIREWALLD_PID" ]]; then
      service_cmd stop firewalld
   fi
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -sR &" true
		sleep $SETUPTIME
	fi
	LOGSZ=$(wc -l $LOGFILE | awk '{print $1}')
	LOGSZ=$(expr $LOGSZ + 1)
	export TIMEOUT=60
	test_run_cmd_local "stress-ng -S $SOCKS --metrics -t 30" true
	export TIMEOUT=30
	tail -n +${LOGSZ} $LOGFILE | grep stress-ng
	if [[ $MODE != "baseline" ]]; then
	    $BPFTUNE_PROG -q summary
	    pkill -TERM bpftune
	    sleep $SETUPTIME
	fi
   done
   if [[ -n "$FIREWALLD_PID" ]]; then
      service_cmd start firewalld
   fi
   test_pass	
   test_cleanup
done

test_exit
