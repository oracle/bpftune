# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#

PERF_TESTS = iperf3_test qperf_test

TUNER_TESTS = sysctl_test log_test

DEFAULT_TESTS = $(TUNER_TESTS) $(PERF_TESTS)

TESTS = $(DEFAULT_TESTS)

LIBS = test_lib.sh

INSTALLFILES = $(DEFAULT_TESTS:%=%.sh) $(LIBS)

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)/lib/tcptune_test/

install_sh_PROGRAM = install
install_sh_DIR = install -dv

all:
	
PHONY: clean
	
test: $(TESTS)
	
test_perf: $(PERF_TESTS)

test_tuner: $(TUNER_TESTS)
	
install: $(INSTALLFILES)
	$(install_sh_DIR) -d $(INSTALLPATH) ; \
	$(install_sh_PROGRAM) $^ -t $(INSTALLPATH) ; \

$(TESTS): %:%.sh
	bash $<

.PHONY: clean
