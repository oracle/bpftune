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
BPF_CFLAGS := -g -fno-stack-protector -Wall
NL_INCLUDE := /usr/include/libnl3
INCLUDES := -I../include -I$(BPF_INCLUDE) -I$(NL_INCLUDE) -I../include/uapi

INSTALL ?= install

DESTDIR ?= /
prefix ?= /usr
installprefix = $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)

# Prefix path can be /usr, /usr/local or for packaging case
# /path2rpmbuilddir/usr[/local]. We use the /usr path as a guide
# to where to bisect the full path such that everything prior to
# it is considered to be prefix to config path /etc.
confprefix ?= $(shell echo $(prefix) | awk -F /usr '{ printf $1 "/etc" }')
CONF	 = $(DESTDIR)/$(confprefix)
CONFPATH  = $(CONF)/ld.so.conf.d

KERNEL_REL := $(shell uname -r)

ifeq ($(BPFTUNE_VERSION),)
BPFTUNE_VERSION := $(KERNEL_REL)
endif

VERSION = 0.1.3
VERSION_SCRIPT  := libbpftune.map

CFLAGS = -fPIC -Wall -Wextra -march=native -g -I../include -std=c99

CFLAGS += -DBPFTUNE_VERSION='"$(BPFTUNE_VERSION)"' $(INCLUDES)

LDLIBS = -lbpf -ldl -lm -lrt -lcap -lnl-3 -lpthread -lnl-route-3

LDFLAGS += -L. -L/usr/local/lib64

# Try to detect best kernel BTF source
KERNEL_REL := $(shell uname -r)
VMLINUX_BTF_PATHS := /sys/kernel/btf/vmlinux /boot/vmlinux-$(KERNEL_REL)
VMLINUX_BTF_PATH := $(or $(VMLINUX_BTF),$(firstword			       \
					  $(wildcard $(VMLINUX_BTF_PATHS))))

OPATH :=
ifeq ($(SANITIZE),1)
CFLAGS += -fsanitize=address 
OPATH := .sanitize/
endif

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

TUNERS = tcp_buffer_tuner route_table_tuner neigh_table_tuner sysctl_tuner \
	 tcp_cong_tuner netns_tuner net_buffer_tuner

TUNER_OBJS = $(patsubst %,%.o,$(TUNERS))
TUNER_SRCS = $(patsubst %,%.c,$(TUNERS))
TUNER_LIBS = $(patsubst %,$(OPATH)%.so,$(TUNERS))

BPF_TUNERS = $(patsubst %,%.bpf.o,$(TUNERS))

BPF_OBJS = $(BPF_TUNERS) probe.bpf.o
LEGACY_BPF_OBJS = $(patsubst %.bpf.o,%.bpf.legacy.o,$(BPF_OBJS))

BPF_SKELS = $(patsubst %,%.skel.h,$(TUNERS)) probe.skel.h
LEGACY_BPF_SKELS = $(patsubst %.skel.h,%.skel.legacy.h,$(BPF_SKELS))

.DELETE_ON_ERROR:

.PHONY: clean

all: analyze $(OPATH) $(OPATH)bpftune $(TUNER_LIBS)

$(OPATH):
	mkdir $(OPATH)
	
analyze: $(BPF_SKELS) $(LEGACY_BPF_SKELS)
	$(CLANG) --analyze $(INCLUDES) libbpftune.c bpftune.c $(TUNER_SRCS)
clean:
	$(call QUIET_CLEAN, bpftune)
	$(Q)$(RM) $(OPATH)*.o *.d $(OPATH)*.so*
	$(Q)$(RM) *.o *.so*
	$(Q)$(RM) *.skel.*h
	$(Q)$(RM) bpftune

distclean: clean
	$(Q)$(RM) -r .output .sanitize

install: $(OPATH)libbpftune.so $(OPATH)bpftune bpftune.service
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/sbin
	$(INSTALL) $(OPATH)bpftune $(INSTALLPATH)/sbin/bpftune
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib64
	$(INSTALL) $(OPATH)libbpftune.so* $(INSTALLPATH)/lib64
	$(INSTALL) -m 0755 -d $(installprefix)/lib/systemd/system
	$(INSTALL) -m 644 bpftune.service $(installprefix)/lib/systemd/system
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib64/bpftune
	$(INSTALL) $(TUNER_LIBS) $(INSTALLPATH)/lib64/bpftune
	$(INSTALL) -m 0755 -d $(CONF)
	$(INSTALL) -m 0755 -d $(CONFPATH)
	echo $(prefix)/lib64 > $(CONFPATH)/libbpftune.conf
	if [ $(DESTDIR) =  / ]; then ldconfig; fi

$(OPATH)bpftune: bpftune.c $(OPATH)bpftune.o $(OPATH)libbpftune.so
	$(QUIET_LINK)$(CC) $(CFLAGS) $(OPATH)bpftune.o -o $@ \
	$(LDFLAGS) $(LDLIBS) -lbpftune

$(OPATH)libbpftune.so: libbpftune.c ../include/bpftune/libbpftune.h $(OPATH)libbpftune.o
	$(CC) $(CFLAGS) -Wl,--version-script=$(VERSION_SCRIPT) \
			-Wl,--soname,$(notdir $@).$(VERSION) \
			-shared -o $(@).$(VERSION) \
			$(patsubst %.so,%.o,$(@)) \
			$(LDLIBS) $(LDFLAGS) ; \
	rm -f $(@) ; \
	ln -sr $(@).$(VERSION) $(@)

$(TUNER_OBJS): $(BPF_SKELS) $(LEGACY_BPF_SKELS)

$(TUNER_LIBS): $(OPATH)libbpftune.so $(TUNER_OBJS)
	$(CC) $(CFLAGS) -shared -o $(@) $(patsubst $(OPATH)%.so,%.c,$(@)) \
		$(LDLIBS) -lbpftune $(LDFLAGS)

$(OPATH)libbpftune.o: probe.skel.h probe.skel.legacy.h
	$(QUIET_CC)$(CC) $(CFLAGS) -c libbpftune.c -o $@

$(OPATH)bpftune.o: $(OPATH)libbpftune.so
	$(QUIET_CC)$(CC) $(CFLAGS) -c bpftune.c -o $@

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(BPF_OBJS): $(patsubst %.o,%.c,$(BPF_OBJS))
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) -o $(@);

$(LEGACY_BPF_OBJS): $(patsubst %.legacy.o,%.c,$(LEGACY_BPF_OBJS))
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_$(SRCARCH) -DBPFTUNE_LEGACY -O2 -target bpf \
		$(INCLUDES) -c $(patsubst %.legacy.o,%.c,$(@)) \
		-o $(@)

$(BPF_SKELS): $(BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.o,$@) > $@

$(LEGACY_BPF_SKELS): $(LEGACY_BPF_OBJS)
	$(BPFTOOL) gen skeleton $(subst .skel.legacy.h,.bpf.legacy.o,$@) > $(subst .skel.h,.skel.legacy.h,$@)

