# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2020 Intel Corporation.

VAR_CFLAGS :=
VAR_LDLIBS :=
ifeq ($(VAR_LDLIBS),)
VAR_LDLIBS :=
endif

TEST_PROGS := TEST_PREREQUISITES.sh \
              TEST_XSK.sh
TEST_FILES := prereqs.sh
TEST_TRANSIENT_FILES := veth.spec
TEST_PROGS_EXTENDED :=

KSFT_KHDR_INSTALL := 1
include ../lib.mk

override define CLEAN
	$(RM) $(TEST_TRANSIENT_FILES)
endef
