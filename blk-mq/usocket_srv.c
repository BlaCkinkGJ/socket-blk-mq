#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SERV_DEBUG	0

const char *file_path = "/mnt/nvme/data_file";

typedef unsigned long long u64;

#define PORT		4444
#define NUMCLIENT	32
/* op(1B), offset(8B), size(8B) */
#define METASZ		17
#define DATAOFFSET	1
#define DATASIZE	9
#define READ		0
#define WRITE		1

int server_fd;
struct sockaddr_in addr_srv;
int addrlen = sizeof(addr_srv);

void socket_init()
{
	int opt = 1;

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
				&opt, sizeof(opt))) {
		perror("set socket failed");
		exit(EXIT_FAILURE);
	}

	addr_srv.sin_family = AF_INET;
	addr_srv.sin_addr.s_addr = INADDR_ANY;
	addr_srv.sin_port = htons(PORT);

	if (bind(server_fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv))) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, NUMCLIENT)) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}
}

int get_metadata(int client_fd, char *op, u64 *offset, u64 *size)
{
	char metadata[METASZ];
	int len;

	if ((len = recv(client_fd, metadata, METASZ, MSG_WAITALL)) < 0) {
		perror("recv failed");
		return -1;
	}

	memcpy(op, metadata, 1);
	memcpy(offset, metadata+DATAOFFSET, 8);
	memcpy(size, metadata+DATASIZE, 8);
#if SERV_DEBUG
	printf("metadata: op(%c) offset(%llu) size(%llu)\n",
		'0'+*op, *offset, *size);
#endif

	return len != METASZ;
}

int write_data(FILE *f, int client_fd, u64 offset, u64 size) {
	socklen_t addr_len, len;
        char *data;

	data = (char *)malloc(sizeof(char) * size);

	if ((len = recv(client_fd, data, size, MSG_WAITALL)) < 0) {
		perror("recv failed");
		return -1;
	}

#if SERV_DEBUG
	printf("write: offset(%llu) size(%llu)\n", offset, size);
	printf("data: %s\n", data);
#endif
	fseek(f, offset, SEEK_SET);
	fwrite(data, sizeof(char), size, f);

	data[0] = '0';

	// success
	if (send(client_fd, data, 1, MSG_WAITALL) < 0) {
		perror("send failed");
		return 0;
	}

	free(data);

	return len;
}

int read_data(FILE *f, int client_fd, u64 offset, u64 size) {
	int len;
	char *data;

	data = (char *)malloc(sizeof(char) * size);

#if SERV_DEBUG
	printf("read: offset(%llu) size(%llu)\n", offset, size);
#endif
	fseek(f, offset, SEEK_SET);
	fread(data, sizeof(char), size, f);

#if SERV_DEBUG
	printf("  data: %s\n", data);
#endif

	if ((len = send(client_fd, data, size, MSG_WAITALL)) < 0) {
		perror("send failed");
		return 0;
	}

	free(data);

	return len;
}

int main() {
	char op;
	u64 offset, size;
	int client_fd;
	int pid;
	FILE *f = NULL;

	printf("server listen %d...\n", PORT);

	socket_init();

	for (int i=0; i<32; i++) {
		if ((pid=fork()) == 0) {
			while (1) {
				if ((client_fd = accept(server_fd, (struct sockaddr *)&addr_srv,
								(socklen_t *)&addrlen)) < 0) {
					perror("accept failed");
					exit(EXIT_FAILURE);
				}

				f = fopen(file_path, "r+");
				if (!f) {
					perror("open error");
					return 0;
				}

				while (1) {
					if (get_metadata(client_fd, &op, &offset, &size)) {
						break;
					}

					switch (op) {
						case READ:
							read_data(f, client_fd, offset, size);
							break;
						case WRITE:
							write_data(f, client_fd, offset, size);
						default:
							break;
					}
				}

				fclose(f);
				close(client_fd);
			}
		} else if (pid < 0) {
			perror("fork error");
		}
	}

	while (1);

	close(server_fd);

	return 0;
}
