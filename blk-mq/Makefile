CC=gcc
WRITE_OBJS=test.o
WRITE_TEST=test
SERVER_OBJS=usocket_srv.o
SERVER_TEST=usocket_srv
obj-m+=blkdev.o

EXTRA_LDFLAGS := -I/home/suho/socket-blk-mq/ksocket
KBUILD_EXTRA_SYMBOLS='/home/suho/socket-blk-mq/ksocket/Module.symvers'

all: module write server

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

write: $(WRITE_OBJS)
	$(CC) -o $(WRITE_TEST) $^

server: $(SERVER_OBJS)
	$(CC) -o $(SERVER_TEST) $^

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(WRITE_TEST) $(WRITE_OBJS) $(SERVER_OBJS) $(SERVER_TEST)
