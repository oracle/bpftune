# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

SRCARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
				  -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
				  -e s/aarch64.*/arm64/ )

CLANG ?= clang
LLC ?= llc
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
BPF_INCLUDE := /usr/local/include
NL_INCLUDE := /usr/include/libnl3
INCLUDES := -I../include -I$(BPF_INCLUDE) -I$(NL_INCLUDE) -I../include/uapi

INSTALL ?= install

DESTDIR ?=
prefix ?= /usr
installprefix = $(DESTDIR)/$(prefix)

INSTALLPATH = $(installprefix)

KERNEL_REL := $(shell uname -r)

ifeq ($(BPFTUNE_VERSION),)
BPFTUNE_VERSION := $(KERNEL_REL)
endif

VERSION = 0.1.1
VERSION_SCRIPT  := libbpftune.map

CFLAGS = -fPIC -Wall -Wextra -march=native -g -I../include -std=c99

CFLAGS += -DBPFTUNE_VERSION='"$(BPFTUNE_VERSION)"' $(INCLUDES)

LDLIBS = -lbpf -ldl -lnl-3 -lnl-route-3

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

TUNERS = neigh_table_tuner sysctl_tuner cong_tuner

TUNER_OBJS = $(patsubst %,%.o,$(TUNERS))
TUNER_LIBS = $(patsubst %,%.so,$(TUNERS))

BPF_TUNERS = $(patsubst %,%.bpf.o,$(TUNERS))

BPF_SKELS = $(patsubst %,%.skel.h,$(TUNERS))

.DELETE_ON_ERROR:

.PHONY: clean

all: bpftune $(TUNER_LIBS)
	
clean:
	$(call QUIET_CLEAN, bpftune)
	$(Q)$(RM) *.o *.d *.so*
	$(Q)$(RM) *.skel.h vmlinux.h
	$(Q)$(RM) bpftune
	$(Q)$(RM) -r .output

install: libbpftune.so bpftune bpftune.service
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/sbin
	$(INSTALL) bpftune $(INSTALLPATH)/sbin/bpftune
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib64
	$(INSTALL) libbpftune.so* $(INSTALLPATH)/lib64
	$(INSTALL) -m 0755 -d $(installprefix)/lib/systemd/system
	$(INSTALL) bpftune.service $(installprefix)/lib/systemd/system
	$(INSTALL) -m 0755 -d $(INSTALLPATH)/lib64/bpftune
	$(INSTALL) $(TUNER_LIBS) $(INSTALLPATH)/lib64/bpftune

bpftune: bpftune.c bpftune.o
	$(QUIET_LINK)$(CC) $(CFLAGS) bpftune.o -o $@ \
	$(LDFLAGS) $(LDLIBS) -lbpftune

libbpftune.so: libbpftune.c libbpftune.o
	$(CC) $(CFLAGS) -Wl,--version-script=$(VERSION_SCRIPT) \
			-Wl,--soname,libbpftune.so.$(VERSION) \
			-shared -o $(@).$(VERSION) $(patsubst %.so,%.o,$(@)) \
			$(LDLIBS) $(LDFLAGS) ; \
	rm -f libbpftune.so ; \
	ln -s libbpftune.so.$(VERSION) libbpftune.so

$(TUNER_LIBS): libbpftune.so $(BPF_SKELS) $(TUNER_OBJS)
	$(CC) $(CFLAGS) -shared -o $(@) $(patsubst %.so,%.c,$(@)) \
		$(LDLIBS) -lbpftune $(LDFLAGS)

libbpftune.o:
	$(QUIET_CC)$(CC) $(CFLAGS) -c libbpftune.c -o $@

bpftune.o: libbpftune.so
	$(QUIET_CC)$(CC) $(CFLAGS) -c bpftune.c -o $@

%.skel.h: %.bpf.o
	$(QUIET_GEN)$(BPFTOOL) gen skeleton $< > $@

$(BPF_TUNERS): vmlinux.h
	$(CLANG) -g -D__TARGET_ARCH_$(SRCARCH) -O2 -target bpf			\
		$(INCLUDES) -c $(patsubst %.o,%.c,$(@)) -o $(@)

$(BPF_SKELS): $(BPF_TUNERS)
	$(BPFTOOL) gen skeleton $(subst .skel.h,.bpf.o,$@) > $@


vmlinux.h:
	if [ ! -e "$(VMLINUX_BTF_PATH)" ] ; then \
		echo "Couldn't find kernel BTF; set VMLINUX_BTF to"	       \
			"specify its location." >&2;			       \
		exit 1;\
	fi
	$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

