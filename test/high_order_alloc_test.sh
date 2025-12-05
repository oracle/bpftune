#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2025, Oracle and/or its affiliates.
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

# run high order alloc test

. ./test_lib.sh


SLEEPTIME=10

for TUNER in net_buffer ; do

   test_start "$0|high order alloc test: is high order alloc disabled for kernels > 5.14?"

   test_setup "true"

   orig_high_order=$(sysctl -n net.core.high_order_alloc_disable)
   sysctl -w net.core.high_order_alloc_disable=1

   test_run_cmd_local "$BPFTUNE -ds &" true

   sleep $SETUPTIME

   expected=1

   case $MAJ_KVER in
   2|3|4)
	   ;;
   5)
	   if [[ $MIN_KVER -gt 14 ]]; then
		   expected_high_order=0
	   fi
	   ;;
   *)
	   expected=0
	   ;;
   esac

   val="$(sysctl -qn net.core.high_order_alloc_disable)"
   pkill -TERM bpftune
   sysctl -w net.core.high_order_alloc_disable=$orig_high_order
   if [[ "$val" == "$expected" ]]; then
	   test_pass
   fi
   test_cleanup
done

test_exit
