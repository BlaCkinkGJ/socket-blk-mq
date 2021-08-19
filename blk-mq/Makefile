CC=gcc
TEST_OBJS=test.o
TEST_TEST=test
SERVER_OBJS=usocket_srv.o
SERVER_TEST=usocket_srv
PROJECT_ROOT=
obj-m+=blkdev.o

EXTRA_LDFLAGS := -I$(PROJECT_ROOT)/socket-blk-mq/ksocket
KBUILD_EXTRA_SYMBOLS='$(PROJECT_ROOT)/ksocket/Module.symvers'

all: module test server

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test: $(TEST_OBJS)
	$(CC) -o $(TEST_TEST) $^

server: $(SERVER_OBJS)
	aarch64-linux-gnu-gcc -mcpu=cortex-a53 -o $(SERVER_TEST) usocket_srv.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(TEST_TEST) $(TEST_OBJS) $(SERVER_OBJS) $(SERVER_TEST)
