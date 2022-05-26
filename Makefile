# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

.DELETE_ON_ERROR:

.PHONY: all clean

all: srcdir docdir
	
srcdir:
	cd src; make
docdir:
	cd docs; make man

test:	FORCE
	cd test; make test

FORCE:
	
clean: srcclean docclean

srcclean:
	cd src; make clean
docclean:
	cd Documentation; make clean

install: srcinstall docinstall
	
srcinstall:
	cd src; make install
docinstall:
	cd docs; make install
