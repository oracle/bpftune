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

# verify netns/container add/remove is caught by bpftune

# enable proxyt if available...
service proxyt start 2>/dev/null

# ...and skip disable of it during test setup so we can find podman images.
PROXYT_SERVICE=""

. ./test_lib.sh


SLEEPTIME=2


test_setup "true"

for CONTAINER_CMD in "ip netns add testns.$$" "$PODMAN_CMD sleep 5" ; do
 test_start "$0|netns test: does running '${CONTAINER_CMD}' generate event?"

 if [[ ${BPFTUNE_NETNS} -eq 0 ]]; then
	echo "bpftune does not support per-netns policy, skipping..."
	test_pass
	continue
 fi
 if [[ ${CONTAINER_CMD} =~ "$PODMAN_CMD" ]]; then
   if [[ -z "$PODMAN" ]]; then
	echo "podman not available, skipping..."
	test_pass
	continue
   fi
 fi 
 test_run_cmd_local "$BPFTUNE -ds &" true
 sleep $SETUPTIME
 test_run_cmd_local "$CONTAINER_CMD"
 if [[ ${CONTAINER_CMD} =~ "ip netns" ]]; then
	ip netns del testns.$$
 fi
 sleep $SLEEPTIME
 grep "netns created" $TESTLOG_LAST
 test_pass
done
test_cleanup
test_exit
