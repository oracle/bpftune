#!/usr/bin/bash
#
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

# run sysctl test

. ./test_lib.sh


SLEEPTIME=1

test_start "$0|support test: does 'bpftune -S' show support level?"

ARCH=$(uname -m)

MAJ_KVER=$(uname -r | awk -F '.' '{print $1}')
MIN_KVER=$(uname -r | awk -F '.' '{print $2}')

expected="bpftune is not supported"
expected_netns="does not support per-netns policy"

if [[ $MAJ_KVER -gt 4 ]]; then
	if [[ "$MIN_KVER" -gt 3 ]]; then
		expected="bpftune works in legacy mode"
	fi
	case $MAJ_KVER in
	2|3|4)
		;;
	5)
		if [[ $MIN_KVER -gt 14 ]]; then
			expected_netns="supports per-netns policy"
			if [[ "$ARCH" == "x86_64" ]]; then
				expected="bpftune works fully"
			fi	
		fi
		;;
	*)
		expected_netns="supports per-netns policy"
		if [[ "$ARCH" == "x86_64" ]]; then
			expected="bpftune works fully"
		fi
		;;
	esac
fi

SUPPORT=$($BPFTUNE_PROG -S 2>&1)

if [[ "$SUPPORT" =~ $expected ]]; then
	if [[ "$SUPPORT" =~ $expected_netns ]]; then
		test_pass
	fi
fi

test_cleanup
test_exit
