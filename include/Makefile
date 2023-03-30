# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
#


INSTALLFILES = $(wildcard bpftune/*.h)

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)/include

install_sh_HDR = install -m 0444
install_sh_DIR = install -dv

all:
	
install: $(INSTALLFILES)
	$(install_sh_DIR) -d $(INSTALLPATH)/bpftune ; \
	$(install_sh_HDR) $^ -t $(INSTALLPATH)/bpftune ; \

