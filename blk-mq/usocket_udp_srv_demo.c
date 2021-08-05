#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 4444
#define BUF_SIZE 1024

int main() {
  int sockfd;
  char buf[BUF_SIZE];
  struct sockaddr_in addr_srv;
  struct sockaddr_in addr_cli;
  socklen_t addr_len, len;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&addr_srv, 0, sizeof(addr_srv));
  memset(&addr_cli, 0, sizeof(addr_cli));

  addr_srv.sin_family = AF_INET;
  addr_srv.sin_addr.s_addr = INADDR_ANY;
  addr_srv.sin_port = htons(PORT);

  addr_len = sizeof(struct sockaddr_in);

  if (bind(sockfd, (const struct sockaddr *)&addr_srv, addr_len) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  while(1) {
    memset(buf, 0, sizeof(buf));
    len = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&addr_cli, &addr_len);
    if (len > 0)  {
      printf("got message: %s\n", buf);
    }
  }
}
