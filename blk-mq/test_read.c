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

#define BUFLEN 1024
#define DEV_NAME "/dev/socketdev0"

char buf[BUFLEN];
int fd;
int i;
off_t off;

int main() {
	if ((fd = open(DEV_NAME, O_RDWR | O_SYNC)) < 0) {
		perror("open error");
		return -1;
	}

	lseek(fd, 0, SEEK_SET);
	if (read(fd, buf, BUFLEN) < 0) {
		perror("read error");
		goto out;
	}

	printf("read: %s\n", buf);
out:
	if (close(fd) != 0) {
		perror("close error");
		return -1;
	}

	return 0;
}
