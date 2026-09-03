
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = \
	filter_stderr

EXTRA_DIST = $(noinst_SCRIPTS) \
	isa.stderr.exp isa.stdout.exp isa.vgtest \
	sigtest.stderr.exp sigtest.stdout.exp sigtest.vgtest

check_PROGRAMS = \
	isa \
	sigtest

AM_CFLAGS   += $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS += $(AM_FLAG_M3264_PRI)
