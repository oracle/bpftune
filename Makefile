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

PKG_NAME = `rpmspec -q --queryformat="%{NAME}-%{VERSION}-%{RELEASE}\n" buildrpm/bpftune.spec | head -1`.`uname -m`
PKG_ARCHIVE = `rpmspec -q --queryformat="%{NAME}-%{VERSION}\n" buildrpm/bpftune.spec | head -1`
PKG_DIR ?=  ${HOME}/rpmbuild
SRC_DIR = $(PKG_DIR)/SOURCES
THIS_DIR = `basename $PWD`
LICENSEDIR ?= $(PKG_DIR)/BUILD
BUILD_DIR = $(PKG_DIR)/BUILDROOT/$(PKG_NAME)

DESTDIR ?=
prefix ?= /usr
installprefix ?= $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)

.DELETE_ON_ERROR:

.PHONY: all clean

all: srcdir docdir testdir
	
srcdir:
	cd src; make
docdir:
	cd docs; make man

testdir: srcdir
	cd test; make

test:	FORCE
	cd test; make test

pkg:    all
	mkdir -p $(SRC_DIR) $(BUILD_DIR) $(BUILD_DIR)/$(prefix) $(LICENSEDIR);\
	rm -fr $(SRC_DIR)/$(PKG_ARCHIVE)* ;\
	git archive --format=tar --prefix=$(PKG_ARCHIVE)/ -o $(SRC_DIR)/$(PKG_ARCHIVE).tar HEAD;\
	bzip2 $(SRC_DIR)/$(PKG_ARCHIVE).tar ; \
	cp -pr LICENSE* $(LICENSEDIR) ;\
	DESTDIR=$(BUILD_DIR) installprefix=$(BUILD_DIR)/$(prefix) rpmbuild --define "_topdir $(PKG_DIR)" -ba buildrpm/bpftune.spec

FORCE:
	
clean: srcclean docclean testclean

distclean: clean distclean_src
	
srcclean:
	cd src; make clean
docclean:
	cd docs; make clean
distclean_src:
	cd src; make distclean
testclean:
	cd test; make clean

install: srcinstall includeinstall docinstall pcpinstall
	
srcinstall:
	cd src; make install
includeinstall:
	cd include; make install
docinstall:
	cd docs; make install
pcpinstall:
	cd src/pcp; make install
