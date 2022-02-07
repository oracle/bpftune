# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

include Makefile.arch

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
BPF_INCLUDE := /usr/local/include
INCLUDES := -I../include -I$(BPF_INCLUDE) -I../include/uapi

INSTALL ?= install

KERNEL_REL := $(shell uname -r)

ifeq ($(BPFTUNE_VERSION),)
BPFTUNE_VERSION := $(KERNEL_REL)
endif

VERSION = 0.1.1
VERSION_SCRIPT  := libbpftune.map

CFLAGS = -fPIC -Wall -Wextra -march=native -g -I../include

CFLAGS += -DBPFTUNE_VERSION='"$(BPFTUNE_VERSION)"'

LDLIBS = -lbpf -ldl

LDFLAGS += -L.

# Try to detect best kernel BTF source
KERNEL_REL := $(shell uname -r)
VMLINUX_BTF_PATHS := /sys/kernel/btf/vmlinux /boot/vmlinux-$(KERNEL_REL)
VMLINUX_BTF_PATH := $(or $(VMLINUX_BTF),$(firstword			       \
					  $(wildcard $(VMLINUX_BTF_PATHS))))

ifeq ($(V),1)
Q =
else
Q = @
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

TUNERS = neigh_table_tuner

TUNER_OBJS = $(patsubst %,%.so,$(TUNERS))

BPF_TUNERS = $(patsubst %,%.bpf,$(TUNERS))

BPF_SKELS = $(patsubst %,%.skel.h,$(TUNERS))

.DELETE_ON_ERROR:

.PHONY: all clean bpftune
all: bpftune $(TUNERS)
	
clean:
	$(call QUIET_CLEAN, bpftune)
	$(Q)$(RM) *.o *.d *.so.*
	$(Q)$(RM) *.skel.h vmlinux.h
	$(Q)$(RM) bpftune
	$(Q)$(RM) -r .output

install: bpftune
	$(call QUIET_INSTALL, bpftune)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) bpftune $(DESTDIR)$(prefix)/sbin/bpftune
	$(Q)$(INSTALL) libbpftune.so.$(VERSION) $(DESTDIR)$(prefix)/lib64
	$(Q)$(INSTALL) $(TUNER_OBJS) $(DESTDIR)$(prefix)/lib64

bpftune: bpftune.c bpftune.o libbpftune
	$(QUIET_LINK)$(CC) $(CFLAGS) bpftune.o -o $@ \
		$(LDFLAGS) $(LDLIBS) -lbpftune

libbpftune: bpftune.c libbpftune.o
	$(CC) $(CFLAGS) -Wl,--version-script=$(VERSION_SCRIPT) \
			-Wl,--soname,libbpftune.so.$(VERSION) \
			-shared -o $@.so.$(VERSION) $(@).o \
			$(LDLIBS) $(LDFLAGS)
	rm libbpftune.so
	ln -s libbpftune.so.$(VERSION) libbpftune.so

$(TUNERS): libbpftune $(TUNERS:%=%.bpf) $(TUNERS:%=%.skel.h)
	$(CC) $(CFLAGS) -shared -o $(@).so $(@).c \
		$(LDLIBS) -lbpftune $(LDFLAGS)

libbpftune.o:
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c libbpftune.c -o $@

bpftune.o: libbpftune.o
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c bpftune.c -o $@

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(BPF_TUNERS): vmlinux.h
	$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf			\
		$(INCLUDES) -c $(@).c -o $(@).o &&		\
	$(LLVM_STRIP) -g $(@).o

$(BPF_SKELS): $(BPF_TUNERS)
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $(<).o > $@


vmlinux.h: $(VMLINUX_BTF_PATH)
	if [ ! -e "$(VMLINUX_BTF_PATH)" ] ; then \
		echo "Couldn't find kernel BTF; set VMLINUX_BTF to"	       \
			"specify its location." >&2;			       \
		exit 1;\
	fi
	$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

