#!/usr/bin/bash
#
# SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.

# verify netns/container add/remove is caught by bpftune

. ./test_lib.sh


SLEEPTIME=2


test_setup "true"

for CONTAINER_CMD in "ip netns add testns.$$" "$PODMAN_CMD sleep 5" ; do
 test_start "$0|netns legacy test: does running '${CONTAINER_CMD}' generate event?"

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
 test_run_cmd_local "$BPFTUNE -dsL &" true
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
