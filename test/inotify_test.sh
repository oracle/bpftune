#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note 
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.

# check removal/addition of tuners is noticed.

. ./test_lib.sh


SLEEPTIME=10

for TUNER in neigh_table ; do

   test_start "$0|inotify test: do we notice removal/addition of tuner?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SETUPTIME

   cp /usr/lib64/bpftune/tcp_buffer_tuner.so /tmp
   rm /usr/lib64/bpftune/tcp_buffer_tuner.so
   
   sleep $SLEEPTIME
   grep "fini tuner" $TESTLOG_LAST

   sleep $SLEEPTIME

   cp /tmp/tcp_buffer_tuner.so /usr/lib64/bpftune

   sleep $SLEEPTIME
   grep "added lib" $TESTLOG_LAST

   test_pass

   test_cleanup
done

test_exit
