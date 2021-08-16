CC=gcc
READ_OBJS=test_read.o
READ_TEST=test_read
WRITE_OBJS=test_write.o
WRITE_TEST=test_write
SERVER_OBJS=usocket_srv.o
SERVER_TEST=usocket_srv
obj-m+=blkdev.o

EXTRA_LDFLAGS := -I/home/suho/oslab/socket-blk-mq/ksocket
KBUILD_EXTRA_SYMBOLS='/home/suho/oslab/socket-blk-mq/ksocket/Module.symvers'

all: module test_read test_write server

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test_read: $(READ_OBJS)
	$(CC) -o $(READ_TEST) $^

test_write: $(WRITE_OBJS)
	$(CC) -o $(WRITE_TEST) $^

server: $(SERVER_OBJS)
	$(CC) -o $(SERVER_TEST) $^

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf $(READ_TEST) $(READ_OBJS) $(WRITE_TEST) $(WRITE_OBJS) $(SERVER_OBJS) $(SERVER_TEST)
