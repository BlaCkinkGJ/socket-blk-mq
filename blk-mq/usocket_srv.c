#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

const char *file_path = "/home/suho/oslab/socket-blk-mq/data_file";

typedef unsigned long long u64;

#define PORT		4444
/* op(1B), offset(8B), size(8B) */
#define METASZ		17
#define DATAOFFSET	1
#define DATASIZE	9
#define READ		0
#define WRITE		1

int socket_init()
{
	int sockfd, newsocket;
	int opt = 1;
	struct sockaddr_in addr_srv;
	int addrlen = sizeof(addr_srv);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				&opt, sizeof(opt))) {
		perror("set socket failed");
		exit(EXIT_FAILURE);
	}

	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_srv.sin_port = htons(PORT);

	if (bind(sockfd, (struct sockaddr *)&addr_srv, sizeof(addr_srv)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, 1) < 0) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}

	if ((newsocket = accept(sockfd, (struct sockaddr *)&addr_srv,
					(socklen_t *)&addrlen)) < 0) {
		perror("accept failed");
		exit(EXIT_FAILURE);
	}

	return newsocket;
}

int get_metadata(int sockfd, char *op, u64 *offset, u64 *size)
{
	char metadata[METASZ];
	int len;

	if ((len = recv(sockfd, metadata, METASZ, MSG_WAITALL)) < 0) {
		perror("recv failed");
		return -1;
	}

	memcpy(op, metadata, 1);
	memcpy(offset, metadata+DATAOFFSET, 8);
	memcpy(size, metadata+DATASIZE, 8);

	printf("metadata: op(%c) offset(%llu) size(%llu)\n",
		'0'+*op, *offset, *size);

	return len == METASZ;
}

int write_data(int sockfd, u64 offset, u64 size) {
	socklen_t addr_len, len;
        char *data;
	FILE *f;

	data = (char *)malloc(sizeof(char) * size);

	if ((len = recv(sockfd, data, size, MSG_WAITALL)) < 0) {
		perror("recv failed");
		return -1;
	}

	f = fopen(file_path, "r+");
	if (!f) {
		perror("open error");
		return 0;
	}

	printf("write: offset(%llu) size(%llu)\n", offset, size);
	printf("data: %s\n", data);

	fseek(f, offset, SEEK_SET);
	fwrite(data, sizeof(char), size, f);
	fclose(f);

	free(data);

	return len;
}

int read_data(int sockfd, u64 offset, u64 size) {
	int len;
        char *data;
	FILE *f;

	data = (char *)malloc(sizeof(char) * size);

	f = fopen(file_path, "r");
	if (!f)
		return 0;

	printf("read: offset(%llu) size(%llu)\n", offset, size);

	fseek(f, offset, SEEK_SET);
	fread(data, sizeof(char), size, f);
	fclose(f);

	printf("data: %s\n", data);

	if ((len = send(sockfd, data, size, MSG_WAITALL)) < 0) {
		perror("send failed");
		return 0;
	}

	free(data);

	return len;

}

int main() {
	int sockfd;
	char op;
	u64 offset, size;

	printf("server listen %d...\n", PORT);

	sockfd = socket_init();

	while (get_metadata(sockfd, &op, &offset, &size)) {
		switch (op) {
		case READ:
			read_data(sockfd, offset, size);
			break;
		case WRITE:
			write_data(sockfd, offset, size);
		default:
		break;
		}
	}
}
