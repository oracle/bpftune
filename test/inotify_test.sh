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

# check removal/addition of tuners is noticed.

. ./test_lib.sh


SLEEPTIME=20

for TUNER in neigh_table ; do

   test_start "$0|inotify test: do we notice removal/addition of tuner?"

   test_setup "true"

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SETUPTIME

   cp -f ${BPFTUNE_LIBDIR}/tcp_buffer_tuner.so /tmp
   rm ${BPFTUNE_LIBDIR}/tcp_buffer_tuner.so

   sleep $SLEEPTIME
   grep "fini tuner" $TESTLOG_LAST

   install -o root -g root -m 0755 /tmp/tcp_buffer_tuner.so \
      ${BPFTUNE_LIBDIR}/tcp_buffer_tuner.so
   rm -f /tmp/tcp_buffer_tuner.so

   sleep $SLEEPTIME
   grep "added lib" $TESTLOG_LAST

   test_pass

   test_cleanup
done

test_exit
