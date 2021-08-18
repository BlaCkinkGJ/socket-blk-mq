#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

const char *file_path = "/mnt/nvme/data_file";

typedef unsigned long long u64;

#define PORT		4444
#define NUMCLIENT	50
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

	if (bind(server_fd, (struct sockaddr *)&addr_srv, sizeof(addr_srv)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	if (listen(server_fd, NUMCLIENT) < 0) {
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

	printf("metadata: op(%c) offset(%llu) size(%llu)\n",
		'0'+*op, *offset, *size);

	return len == METASZ;
}

int write_data(int client_fd, u64 offset, u64 size) {
	socklen_t addr_len, len;
        char *data;
	FILE *f;

	data = (char *)malloc(sizeof(char) * size);

	if ((len = recv(client_fd, data, size, MSG_WAITALL)) < 0) {
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

int read_data(int client_fd, u64 offset, u64 size) {
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

	printf("  data: %s\n", data);

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

	printf("server listen %d...\n", PORT);

	socket_init();

	while (1) {
		if ((client_fd = accept(server_fd, (struct sockaddr *)&addr_srv,
						(socklen_t *)&addrlen)) < 0) {
			perror("accept failed");
			exit(EXIT_FAILURE);
		}

		if ((pid=fork()) == 0) {
			close(server_fd);

			get_metadata(client_fd, &op, &offset, &size);

			switch (op) {
				case READ:
					read_data(client_fd, offset, size);
					break;
				case WRITE:
					write_data(client_fd, offset, size);
				default:
					break;
			}

			close(client_fd);

			exit(0);
		} else if (pid < 0) {
			perror("fork error");
		} else {
			close(client_fd);
		}
	}

	close(server_fd);

	return 0;
}
