# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020 Authors of Cilium

include ../../Makefile.defs

.PHONY: all clean

BPF = bpf_custom.o

include ../Makefile.bpf

all: $(BPF)

%.ll: %.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} -c $< -o $@

$(BPF): %.o: %.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -fr *.o *.ll *.i
