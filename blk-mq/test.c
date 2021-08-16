// [[ reference ]]
// - name: [Linux Kernel 5] Block Device Driver Example
// - author: pr0gr4m
// - link:
// https://pr0gr4m.tistory.com/entry/Linux-Kernel-5-Block-Device-Driver-Example
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUF_LEN 1024
#define DEV_NAME "/dev/socketdev0"

int main() {
	static char buf[BUF_LEN];
	int fd;
	int i;
	off_t off;

	if ((fd = open(DEV_NAME, O_RDWR | O_SYNC | O_DIRECT)) < 0) {
		perror("open error");
		return -1;
	}

	for (i = 0; i < 10000; i++) {
		sprintf(buf, "%d", i);
		// lseek(fd, 0, SEEK_SET);
		if (write(fd, buf, sizeof(int)) < 0) {
			perror("write error");
			return -1;
		}
	}

	if (close(fd) != 0) {
		perror("close error");
		return -1;
	}

	return 0;
}
