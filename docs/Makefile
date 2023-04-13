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

INSTALL ?= install
RM ?= rm -f
RMDIR ?= rmdir --ignore-fail-on-non-empty

ifeq ($(V),1)
  Q =
else
  Q = @
endif

DESTDIR ?=
prefix ?= /usr/share
installprefix = $(DESTDIR)/$(prefix)

mandir ?= $(prefix)/man
man8dir = $(mandir)/man8

MAN8_RST = bpftune.rst bpftune-sysctl.rst bpftune-cong.rst bpftune-neigh.rst \
	   bpftune-tcp-buffer.rst bpftune-netns.rst

_DOC_MAN8 = $(patsubst %.rst,%.8,$(MAN8_RST))
DOC_MAN8 = $(addprefix $(OUTPUT),$(_DOC_MAN8))

man: man8
man8: $(DOC_MAN8)

RST2MAN_DEP := $(shell command -v rst2man 2>/dev/null)
RST2MAN_OPTS += --verbose

list_pages = $(sort $(basename $(filter-out $(1),$(MAN8_RST))))
see_also = $(subst " ",, \
	"\n" \
	"SEE ALSO\n" \
	"========\n" \
	"\t**bpf**\ (2),\n")

$(OUTPUT)%.8: %.rst
	$(QUIET_GEN)( cat $< ; printf "%b" $(call see_also,$<) ) | rst2man $(RST2MAN_OPTS) > $@

clean:
	$(call QUIET_CLEAN, Documentation)
	$(Q)$(RM) $(DOC_MAN8)

install: man
	$(call QUIET_INSTALL, Documentation-man)
	$(Q)$(INSTALL) -d -m 755 $(DESTDIR)$(man8dir)
	$(Q)$(INSTALL) -m 644 $(DOC_MAN8) $(DESTDIR)$(man8dir)

uninstall:
	$(call QUIET_UNINST, Documentation-man)
	$(Q)$(RM) $(addprefix $(DESTDIR)$(man8dir)/,$(_DOC_MAN8))
	$(Q)$(RMDIR) $(DESTDIR)$(man8dir)

.PHONY: man man8 clean install uninstall
.DEFAULT_GOAL := man
