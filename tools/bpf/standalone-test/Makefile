include ../../scripts/Makefile.include
include ../../scripts/utilities.mak

ifeq ($(srctree),)
srctree := $(patsubst %/,%,$(dir $(CURDIR)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
srctree := $(patsubst %/,%,$(dir $(srctree)))
endif

ifeq ($(V),1)
  Q =
else
  Q = @
endif

BPF_DIR = $(srctree)/tools/lib/bpf/

ifneq ($(OUTPUT),)
  BPF_PATH = $(OUTPUT)
else
  BPF_PATH = $(BPF_DIR)
endif

LIBBPF = $(BPF_PATH)libbpf.a

TEST_PROGS_VERSION := $(shell make --no-print-directory -sC ../../.. kernelversion)

$(LIBBPF): FORCE
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) $(OUTPUT)libbpf.a

$(LIBBPF)-clean:
	$(call QUIET_CLEAN, libbpf)
	$(Q)$(MAKE) -C $(BPF_DIR) OUTPUT=$(OUTPUT) clean >/dev/null

prefix ?= /usr/local
bash_compdir ?= /usr/share/bash-completion/completions

CC = $(CROSS_COMPILE)gcc

CFLAGS += -O2
CFLAGS += -W -Wall -Wextra -Wno-unused-parameter -Wshadow -Wno-missing-field-initializers
CFLAGS += -DPACKAGE='"test_progs"' -D__EXPORTED_HEADERS__ \
	-I$(srctree)/kernel/bpf/ \
	-I$(srctree)/tools/include \
	-I$(srctree)/tools/include/uapi \
	-I$(srctree)/tools/lib/bpf \
	-I$(srctree)/tools/perf
CFLAGS += -DTEST_PROGS_VERSION='"$(TEST_PROGS_VERSION)"'
ifneq ($(EXTRA_CFLAGS),)
CFLAGS += $(EXTRA_CFLAGS)
endif
ifneq ($(EXTRA_LDFLAGS),)
LDFLAGS += $(EXTRA_LDFLAGS)
endif

LIBS = -lelf -lbfd -lopcodes $(LIBBPF)

INSTALL ?= install
RM ?= rm -f

FEATURE_USER = .test_progs
FEATURE_TESTS = libbfd disassembler-four-args reallocarray
FEATURE_DISPLAY = libbfd disassembler-four-args

check_feat := 1
NON_CHECK_FEAT_TARGETS := clean uninstall
ifdef MAKECMDGOALS
ifeq ($(filter-out $(NON_CHECK_FEAT_TARGETS),$(MAKECMDGOALS)),)
  check_feat := 0
endif
endif

ifeq ($(check_feat),1)
ifeq ($(FEATURES_DUMP),)
include $(srctree)/tools/build/Makefile.feature
else
include $(FEATURES_DUMP)
endif
endif

ifeq ($(feature-disassembler-four-args), 1)
CFLAGS += -DDISASM_FOUR_ARGS_SIGNATURE
endif

ifeq ($(feature-reallocarray), 0)
CFLAGS += -DCOMPAT_NEED_REALLOCARRAY
endif

include $(wildcard $(OUTPUT)*.d)

all: $(OUTPUT)test_progs

OBJS = $(OUTPUT)test_progs.o $(OUTPUT)trace_helpers.o $(OUTPUT)disasm.o

$(OUTPUT)disasm.o: $(srctree)/kernel/bpf/disasm.c
	$(QUIET_CC)$(COMPILE.c) -MMD -o $@ $<

$(OUTPUT)test_progs: $(OBJS) $(LIBBPF)
	$(QUIET_LINK)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OUTPUT)%.o: %.c
	$(QUIET_CC)$(COMPILE.c) -MMD -o $@ $<

clean: $(LIBBPF)-clean
	$(call QUIET_CLEAN, test_progs)
	$(Q)$(RM) $(OUTPUT)test_progs $(OUTPUT)*.o $(OUTPUT)*.d
	$(call QUIET_CLEAN, core-gen)
	$(Q)$(RM) $(OUTPUT)FEATURE-DUMP.test_progs

install: $(OUTPUT)test_progs
	$(call QUIET_INSTALL, test_progs)
	$(Q)$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/sbin
	$(Q)$(INSTALL) $(OUTPUT)test_progs $(DESTDIR)$(prefix)/sbin/test_progs

uninstall:
	$(call QUIET_UNINST, test_progs)
	$(Q)$(RM) $(DESTDIR)$(prefix)/sbin/test_progs
	$(Q)$(RM) $(DESTDIR)$(bash_compdir)/test_progs


FORCE:

.PHONY: all FORCE clean install uninstall
.DEFAULT_GOAL := all
