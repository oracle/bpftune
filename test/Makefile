# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#

PERF_TESTS = iperf3_test qperf_test

TUNER_TESTS =	sysctl_test log_test netns_test neigh_table_test \
		cong_test \
		mem_pressure_test mem_exhaust_test \
		wmem_test rmem_test

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
	bash $<

PHONY: clean
