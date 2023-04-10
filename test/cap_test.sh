#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# verify caps are dropped by bpftune after init

BPFTUNE_FLAGS="-s"

. ./test_lib.sh


SLEEPTIME=1

test_start "$0|cap test: are caps dropped by bpftune after init?"

test_setup "true"

for BPFTUNECMD in "$BPFTUNE &" "service bpftune start" ; do
  test_start "$0|cap test: are caps dropped by '$BPFTUNECMD' after init?"
  test_run_cmd_local "$BPFTUNECMD" true

  sleep $SETUPTIME

  caps=$(getpcaps $(pgrep bpftune) 2>&1 | \
         awk '/cap_net_admin,cap_sys_chroot,cap_sys_admin[+=]p/ { print $0 }')

  echo "caps: $caps"

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
