#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUFFSIZE 4
#define SEED 100

int main(int argc, char** argv) {
	int n;
	int sockfd;
	int connfd;
	int heartvalue;
	socklen_t addr_len;
	char buff[BUFFSIZE];
	struct sockaddr_in serv_addr;

	if(argc != 3) {
		fprintf(stderr, "Usage: %s <ip_address> <port>.\n", argv[0]);

		return EXIT_FAILURE;
	}
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket failed");
		return EXIT_FAILURE;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("connect failed");
		return EXIT_FAILURE;
	}

	printf("Connected.\n");
	
	srand(SEED);
	heartvalue = rand();
	memset(buff, 0, BUFFSIZE);
	memcpy(buff, &heartvalue, sizeof(int));
	
	while(1) {
		printf("Sending...\n");
		write(sockfd, buff, sizeof(int));
		read(sockfd, buff, sizeof(int));
		(*(int*)buff)++;
		sleep(2);
	}
	
	return 0;
}
