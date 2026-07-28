#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2026, Oracle and/or its affiliates.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public
# License v2 as published by the Free Software Foundation.
#

# Verify that a valid tuner in a directory with an untrusted ancestor is not
# loaded. /tmp is normally world-writable, even though this test creates the
# child directory as root.

. ./test_lib.sh

export SLEEPTIME=20

UNTRUSTED_DIR=$(mktemp -d /tmp/bpftune-untrusted.XXXXXX)
UNTRUSTED_TUNER="${UNTRUSTED_DIR}/untrusted_tuner.so"

test_start "$0|plugin path test: reject tuner from an untrusted directory"
test_setup "true"

cp ${BPFTUNE_LIBDIR}/tcp_buffer_tuner.so "$UNTRUSTED_TUNER"
# Do not use -a here: it filters the mandatory packaged tuners, causing
# bpftune to exit before it scans the optional -l directory.
test_run_cmd_local "$BPFTUNE -dsl $UNTRUSTED_DIR &" true
sleep $SLEEPTIME
grep "refusing untrusted plugin" "$TESTLOG_LAST"

rm -rf "$UNTRUSTED_DIR"
test_pass
test_cleanup
test_exit
