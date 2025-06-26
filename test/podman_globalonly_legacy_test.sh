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

. ./test_lib.sh

check_podman

SLEEPTIME=20
TIMEOUT=30

for FAMILY in ipv4 ; do

   SYSCTL_NAME="net.ipv4.ipfrag_high_thresh"

   test_start "$0|podman sysctl test (non-namespaced $SYSCTL_NAME)"

   if [[ -z $PODMAN ]]; then
	echo "podman not supported, skipping"
	test_pass
	continue
   fi
   if [[ ${BPFTUNE_NETNS} -eq 0 ]]; then
	echo "bpftune does not support per-netns policy, skipping..."
	test_pass
	continue
   fi
   test_setup true

   frag_pre=$(sysctl -qn $SYSCTL_NAME)
   sysctl -w ${SYSCTL_NAME}=8192
   container=
   for MODE in baseline test ; do

	echo "Running ${MODE}..."
	test_run_cmd_local "$PODMAN_CMD sleep $SLEEPTIME &" true
	if [[ $MODE != "baseline" ]]; then
		test_run_cmd_local "$BPFTUNE -sL &" true
	fi
	sleep $SETUPTIME
	for (( i=0; i < 5; i++ ))
	do
		container=$(ip netns show | awk '/^netns/ { print $1 }')
		if [[ -n "$container" ]]; then
			break
		fi
		sleep 1
	done
	if [[ -z "$container" ]]; then
		test_cleanup
	fi
	container_ip=$(ip netns exec $container ip addr show dev eth0 | awk '/inet / { split($2, a, "/"); print a[1] }')
	ip netns exec $container  ethtool --offload eth0 rx off tx off gso off gro off lro off tso off
	set +e
	ping -v -c 20 -M want -s 8192 $container_ip
	set -e
   done
   frag_post=$(sysctl -qn $SYSCTL_NAME)
   sysctl -w ${SYSCTL_NAME}=${frag_pre}
   echo "$SYSCTL_NAME pre-test 8192, after $frag_post"
   if [[ "$frag_post" -gt "8192" ]]; then
	   test_pass
   fi

   test_cleanup
done

test_exit
