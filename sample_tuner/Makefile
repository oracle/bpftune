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

SRCARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
				  -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
				  -e s/aarch64.*/arm64/ )

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
BPF_INCLUDE := /usr/include
NL_INCLUDE := /usr/include/libnl3
INCLUDES := -I$(BPF_INCLUDE) -I$(NL_INCLUDE) -I/usr/include/uapi

INSTALL ?= install

DESTDIR ?=
prefix ?= /usr
installprefix = $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)

CFLAGS = -fPIC -Wall -Wextra -march=native -g -I../include -std=c99

CFLAGS += -DBPFTUNE_VERSION='"$(BPFTUNE_VERSION)"' $(INCLUDES)

LDLIBS = -lbpf -ldl -lm -lcap -lpthread

LDFLAGS += -L. -L/usr/local/lib64

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

TUNERS = sample_tuner

TUNER_OBJS = $(patsubst %,%.o,$(TUNERS))
TUNER_LIBS = $(patsubst %,%.so,$(TUNERS))

BPF_TUNERS = $(patsubst %,%.bpf.o,$(TUNERS))

BPF_OBJS = $(BPF_TUNERS)

BPF_SKELS = $(patsubst %,%.skel.h,$(TUNERS))

.DELETE_ON_ERROR:

.PHONY: clean

all: $(TUNER_LIBS)
	
clean:
	$(Q)$(RM) *.o *.d *.so*
	$(Q)$(RM) *.skel*.h
	$(Q)$(RM) -r .output

install: all
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/local/lib64
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/local/lib64/bpftune
	$(INSTALL) $(TUNER_LIBS) $(INSTALLPATH)/local/lib64/bpftune

$(TUNER_LIBS): $(BPF_SKELS) $(TUNER_OBJS)
	$(CC) $(CFLAGS) -shared -o $(@) $(patsubst %.so,%.c,$(@)) \
		$(LDLIBS) -lbpftune $(LDFLAGS)

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(BPF_OBJS): $(patsubst %.o,%.c,$(BPF_OBJS))
	$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf			\
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) -o $(@);
	$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -DBPFTUNE_LEGACY -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) \
		-o $(patsubst %.o,%.legacy.o,$(@));
	$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -DBPFTUNE_NOBTF -DBPFTUNE_LEGACY -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) \
		-o $(patsubst %.o,%.nobtf.o,$(@));

$(BPF_SKELS): $(BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.o,$@) > $@ ;\
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.legacy.o,$@) > $(subst .skel.h,.skel.legacy.h,$@);\
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.nobtf.o,$@) > $(subst .skel.h,.skel.nobtf.h,$@)

