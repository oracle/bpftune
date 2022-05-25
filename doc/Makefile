# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2022, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
MANPAGES= bpftune-cong.1 bpftune-sysctl.1
	

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)/share/man/man1

install_MANPAGE = install
install_DIR = install -d

all debug clean test:


install: $(MANPAGES)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_MANPAGE) $^ -t $(INSTALLPATH)

uninstall: $(MANPAGES)
	cd $(INSTALLPATH); rm -f $^
