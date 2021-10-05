# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

include Makefile.arch

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
BPF_INCLUDE := /usr/local/include
INCLUDES := -I. -I$(BPF_INCLUDE) -I../include/uapi

INSTALL ?= install

KERNEL_REL := $(shell uname -r)

ifeq ($(TCPTUNE_VERSION),)
TCPTUNE_VERSION := $(KERNEL_REL)
endif

CFLAGS := -g -Wall
CFLAGS += -DTCPTUNE_VERSION='"$(TCPTUNE_VERSION)"'

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

.DELETE_ON_ERROR:

.PHONY: all clean tcptune
all: tcptune
	
clean:
	$(call QUIET_CLEAN, tcptune)
	$(Q)$(RM) *.o *.d
	$(Q)$(RM) *.skel.h vmlinux.h
	$(Q)$(RM) tcptune
	$(Q)$(RM) -r .output

install: tcptune
	$(call QUIET_INSTALL, tcptune)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) tcptune $(DESTDIR)$(prefix)/sbin/tcptune

tcptune: tcptune.o
	$(QUIET_LINK)$(CC) $(CFLAGS) $^ -lbpf -o $@

tcptune.o: tcptune.h tcptune.skel.h	      \
			tcptune.bpf.o

tcptune.bpf.o: vmlinux.h tcptune.h

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

%.bpf.o: %.bpf.c
	$(QUIET_GEN)$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf \
		$(INCLUDES) -c $(filter %.c,$^) -o $@ &&		   \
	$(LLVM_STRIP) -g $@

%.o: %.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

vmlinux.h: $(VMLINUX_BTF_PATH)
	$(Q)if [ ! -e "$(VMLINUX_BTF_PATH)" ] ; then \
		echo "Couldn't find kernel BTF; set VMLINUX_BTF to"	       \
			"specify its location." >&2;			       \
		exit 1;\
	fi
	$(QUIET_GEN)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

