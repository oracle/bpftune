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
BPF_INCLUDE := ../../include
BPF_CFLAGS := -g -fno-stack-protector -Wall
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

LDFLAGS += -L../../src -L/usr/local/lib64

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

TUNERS = strategy_tuner

TUNER_OBJS = $(patsubst %,%.o,$(TUNERS))
TUNER_LIBS = $(patsubst %,%.so,$(TUNERS))

BPF_TUNERS = $(patsubst %,%.bpf.o,$(TUNERS))

BPF_OBJS = $(BPF_TUNERS)
LEGACY_BPF_OBJS = $(patsubst %.bpf.o,%.bpf.legacy.o,$(BPF_OBJS))
NOBTF_BPF_OBJS = $(patsubst %.bpf.o,%.bpf.nobtf.o,$(BPF_OBJS))

BPF_SKELS = $(patsubst %,%.skel.h,$(TUNERS))
LEGACY_BPF_SKELS = $(patsubst %.skel.h,%.skel.legacy.h,$(BPF_SKELS))
NOBTF_BPF_SKELS = $(patsubst %.skel.h,%.skel.nobtf.h,$(BPF_SKELS))

.DELETE_ON_ERROR:

.PHONY: clean

all: $(TUNER_LIBS)
	
clean:
	$(Q)$(RM) *.o *.d *.so*
	$(Q)$(RM) *.skel*.h
	$(Q)$(RM) -r .output

$(TUNER_LIBS): $(BPF_SKELS) $(TUNER_OBJS)
	$(CC) $(CFLAGS) -shared -o $(@) $(patsubst %.so,%.c,$(@)) \
		$(LDLIBS) -lbpftune $(LDFLAGS)

$(TUNER_OBJS): $(BPF_SKELS) $(LEGACY_BPF_SKELS) $(NOBTF_BPF_SKELS)

$(BPF_OBJS): $(patsubst %.o,%.c,$(BPF_OBJS)) ../../include/bpftune/bpftune.bpf.h
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) -o $(@)

$(LEGACY_BPF_OBJS): $(patsubst %.legacy.o,%.c,$(LEGACY_BPF_OBJS)) ../../include/bpftune/bpftune.bpf.h
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(SRCARCH) -DBPFTUNE_LEGACY -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.legacy.o,%.c,$(@)) \
		-o $(@)

$(NOBTF_BPF_OBJS): $(patsubst %.nobtf.o,%.c,$(NOBTF_BPF_OBJS)) ../../include/bpftune/bpftune.bpf.h
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(SRCARCH) -DBPFTUNE_NOBTF -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.nobtf.o,%.c,$(@)) \
		-o $(@)

$(BPF_SKELS): $(BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.o,$@) > $@

$(LEGACY_BPF_SKELS): $(LEGACY_BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.legacy.h,.bpf.legacy.o,$@) > $(subst .skel.h,.skel.legacy.h,$@)

$(NOBTF_BPF_SKELS): $(NOBTF_BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.nobtf.h,.bpf.nobtf.o,$@) > $(subst .skel.h,.skel.nobtf.h,$@)

