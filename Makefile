CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wno-overlength-strings
LDLIBS_CRYPTO = -lcrypto -lpthread

CORE = src/crypto.c src/packet.c src/processor.c src/handshake.c src/log.c
HDRS = $(wildcard src/*.h)

all: bin/secure_device bin/echo_test

bin:
	mkdir -p bin

bin/secure_device: src/secure_device.c $(CORE) $(HDRS) | bin
	$(CC) $(CFLAGS) -o $@ src/secure_device.c $(CORE) -lnetfilter_queue $(LDLIBS_CRYPTO)

bin/echo_test: tools/echo_test.c | bin
	$(CC) $(CFLAGS) -o $@ $<

bin/test_channel: tests/test_channel.c $(CORE) $(HDRS) | bin
	$(CC) $(CFLAGS) -o $@ tests/test_channel.c $(CORE) $(LDLIBS_CRYPTO)

test: bin/test_channel
	./bin/test_channel

demo: all
	sudo ./scripts/run_demo.sh

clean:
	rm -rf bin logs

.PHONY: all test demo clean
