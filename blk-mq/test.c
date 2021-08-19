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
char op;
int fd;
int i;
off_t off;
unsigned long size;

int op_read(off_t off, unsigned long size)
{
	int ret = 0;

	lseek(fd, off, SEEK_SET);
	if ((ret=read(fd, buf, size)) < 0) {
		perror("read error");
		return ret;
	}

	buf[size] = '\0';

	return 0;
}

int op_write(off_t off, char *data)
{
	int ret; 

	lseek(fd, off, SEEK_SET);
	if ((ret=write(fd, data, strlen(data))) < 0) {
		perror("write error");
		return ret;
	}

	return 0;
}

int main() {
	if ((fd = open(DEV_NAME, O_RDWR | O_SYNC)) < 0) {
		perror("open error");
		return -1;
	}

	while (1) {
		printf("\rop(r=read, w=write, x=exit): ");
		scanf("%c", &op);

		switch (op) {
		case 'r':
			printf("offset: ");
			scanf("%lu", &off);

			printf("size: ");
			scanf("%lu", &size);

			if (op_read(off, size) == 0)
				printf("read: %s\n", buf);
			else
				printf("??\n");
			break;
		case 'w':
			printf("offset: ");
			scanf("%lu", &off);

			printf("data: ");
			scanf("\n%[^\n]", buf);

			if (op_write(off, buf) == 0)
				printf("write: %s\n", buf);
			break;
		case 'x':
			goto out;
			break;
		}
		fflush(stdin);
	}
out:
	if (close(fd) != 0) {
		perror("close error");
		return -1;
	}

	return 0;
}
