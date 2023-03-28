# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

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

all: srcdir docdir sampledir
	
srcdir:
	cd src; make
docdir:
	cd docs; make man

sampledir:
	cd sample_tuner; make

test:	FORCE
	cd test; make test

pkg:    all
	rm -fr $(SRC_DIR)/$(PKG_ARCHIVE)* ;\
	git archive --format=tar --prefix=$(PKG_ARCHIVE)/ -o $(SRC_DIR)/$(PKG_ARCHIVE).tar HEAD;\
	bzip2 $(SRC_DIR)/$(PKG_ARCHIVE).tar ; \
	mkdir -p $(BUILD_DIR) $(BUILD_DIR)/$(prefix) $(LICENSEDIR);\
	cp -pr LICENSE* $(LICENSEDIR) ;\
	DESTDIR=$(BUILD_DIR) installprefix=$(BUILD_DIR)/$(prefix) rpmbuild --define "_topdir $(PKG_DIR)" -ba buildrpm/bpftune.spec

FORCE:
	
clean: srcclean docclean

srcclean:
	cd src; make clean
docclean:
	cd docs; make clean

install: srcinstall includeinstall docinstall
	
srcinstall:
	cd src; make install
includeinstall:
	cd include; make install
docinstall:
	cd docs; make install
