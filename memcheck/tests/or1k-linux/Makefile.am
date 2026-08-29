
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = \
	filter_stderr

EXTRA_DIST = $(noinst_SCRIPTS) \
	memtest.stderr.exp memtest.stdout.exp memtest.vgtest

check_PROGRAMS = \
	memtest

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)
