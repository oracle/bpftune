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
	6)
		expected_netns="supports per-netns policy"
		if [[ "$ARCH" == "x86_64" ]]; then
			expected="bpftune works fully"
		elif [[ $MIN_KVER -gt 4 ]]; then
			expected="bpftune works fully"
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
