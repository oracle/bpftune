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

# verify caps are dropped by bpftune after init

BPFTUNE_FLAGS="-s"

. ./test_lib.sh


SLEEPTIME=1

test_setup "true"

for BPFTUNECMD in "$BPFTUNE &" "service bpftune start" ; do
  test_start "$0|cap test: are caps dropped by '$BPFTUNECMD' after init?"
  test_run_cmd_local "$BPFTUNECMD" true

  sleep $SETUPTIME

  caps=$(getpcaps $(pgrep bpftune) 2>&1)
#         awk '/[+=]p/ { print $0 }')

  echo "caps: $caps"

  for cap in cap_net_admin cap_sys_module cap_sys_chroot cap_sys_admin cap_syslog ; do
    echo $caps | grep -E $cap >/dev/null
  done

  if [[ -n "$caps" ]]; then
    test_pass
  else
    break
  fi
  set +e
  service bpftune stop 2>/dev/null
  pkill -TERM bpftune
  set -e
done

test_cleanup

test_exit
