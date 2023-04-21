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

PERF_TESTS = iperf3_test qperf_test

TUNER_TESTS =	support_test log_test service_test inotify_test cap_test \
		sample_test sample_legacy_test \
		sysctl_test sysctl_legacy_test sysctl_netns_test \
		netns_test netns_legacy_test \
		backlog_test backlog_legacy_test \
		neigh_table_test neigh_table_legacy_test \
		mem_pressure_test mem_pressure_legacy_test \
		mem_exhaust_test mem_exhaust_legacy_test \
		wmem_test wmem_legacy_test \
		rmem_test rmem_legacy_test \
		cong_test cong_legacy_test

DEFAULT_TESTS = $(TUNER_TESTS) $(PERF_TESTS)

TESTS = $(DEFAULT_TESTS)

LIBS = test_lib.sh

PROGS = conn_bomb

OBJS = conn_bomb.o

INSTALLFILES = $(DEFAULT_TESTS:%=%.sh) $(LIBS)

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)/lib/tcptune_test/

install_sh_PROGRAM = install
install_sh_DIR = install -dv

all: $(PROGS)
	
PHONY: clean
	
clean:
	rm -f $(PROGS)

test: $(TESTS)
	
test_perf: $(PERF_TESTS)

test_tuner: $(TUNER_TESTS)
	
install: $(INSTALLFILES)
	$(install_sh_DIR) -d $(INSTALLPATH) ; \
	$(install_sh_PROGRAM) $^ -t $(INSTALLPATH) ; \

$(TESTS): %:%.sh
	TEST_ID=$$PPID  bash $<

PHONY: clean
