# execap Makefile.am source
#
# $Id$

AUTOMAKE_OPTIONS = foreign

#CFLAGS = -Wall -march=native -O3 -DEXECAPVER="\"$(VERSION)\"" -DOLDPCAP=$(OLDPCAP)
CFLAGS = -Wall -O3 -DEXECAPVER="\"$(VERSION)\"" -DOLDPCAP=$(OLDPCAP)
LDFLAGS = -lpcap -lcrypto -lpthread

bin_PROGRAMS = execap
execap_SOURCES = execap.c findexe.c pavl.c
noinst_HEADERS = execap.h pavl.h

man_MANS = execap.1

EXTRA_DIST = $(man_MANS) LICENSE COPYING AUTHORS NEWS ChangeLog README
