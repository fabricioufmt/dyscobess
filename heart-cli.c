#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUFFSIZE 1024
#define SEED 100

struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
};

int main(int argc, char** argv) {
	int n;
	int sockfd;
	int connfd;
	int heartvalue;
	socklen_t addr_len;
	char buff[BUFFSIZE];
	struct sockaddr_in serv_addr;
	struct sockaddr_in client_addr;

	if(argc != 3) {
		fprintf(stderr, "Usage: %s <ip_address> <port>.\n", argv[0]);

		return EXIT_FAILURE;
	}
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket failed");
		return EXIT_FAILURE;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	memset(&client_addr, 0, sizeof(client_addr));
	addr_len = sizeof(client_addr);
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("connect failed");
		return EXIT_FAILURE;
	}

	if(getsockname(sockfd, (struct sockaddr*) &client_addr, &addr_len) < 0) {
		perror("getpeername failed");
		close(sockfd);
		return EXIT_FAILURE;
	}

	printf("%s:%u -> %s:%s Connected.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), argv[1], argv[2]);

	struct tcp_session super;
	super.sip = client_addr.sin_addr.s_addr;
	super.dip = inet_addr(argv[1]);
	super.sport = client_addr.sin_port;
	super.dport = htons(atoi(argv[2]));
	
	int sockfd1 = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd != -1) {
		struct sockaddr_in serv_addr1;
		serv_addr1.sin_family = AF_INET;
		serv_addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
		serv_addr1.sin_port = htons(6998);
		int ret = connect(sockfd1, (struct sockaddr*) &serv_addr1, sizeof(serv_addr1));
		if(ret == 0) {
			n = write(sockfd1, &super, sizeof(struct tcp_session));
			close(sockfd1);
			printf("Super was sent with %d bytes.\n", n);
		} else {
			printf("Failed to connect.\n");
		}
	} else
		printf("Failed to create socket.\n");

	int val;
	while(1) {
		read(sockfd, &val, sizeof(int));
	}
	
	return 0;
}
