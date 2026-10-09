CLANG      ?= clang
CC         ?= gcc
BPF_OBJ    := dns_refused.bpf.o
USER_BIN   := dns_refused
CLIENT_NS  ?= client
SERVER_NS  ?= server

BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror
CFLAGS     := -O2 -g -Wall -Wextra

.PHONY: all clean setup teardown

all: $(BPF_OBJ) $(USER_BIN)

$(BPF_OBJ): src/dns_refused.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): src/dns_refused.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf

setup:
	CLIENT_NS=$(CLIENT_NS) SERVER_NS=$(SERVER_NS) ./scripts/netns.sh setup

teardown:
	CLIENT_NS=$(CLIENT_NS) SERVER_NS=$(SERVER_NS) ./scripts/netns.sh teardown

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
