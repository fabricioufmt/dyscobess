#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define LISTENQ 100
#define BUFFSIZE 4

int main(int argc, char** argv) {
	int n;
	int sockfd;
	int connfd;
	pid_t pid;
	int heartvalue;
	socklen_t addr_len;
	struct sockaddr_in serv_addr;
	struct sockaddr_in conn_addr;

	if(argc != 3) {
		fprintf(stderr, "Usage: %s <port> <usec>.\n", argv[0]);

		return EXIT_FAILURE;
	}
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket failed");
		return EXIT_FAILURE;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(atoi(argv[1]));

	if(bind(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("bind failed");
		return EXIT_FAILURE;
	}

	if(listen(sockfd, LISTENQ) == -1) {
		perror("listen failed");
		return EXIT_FAILURE;
	}

	while(1) {
		memset(&conn_addr, 0, sizeof(struct sockaddr_in));
		if((connfd = accept(sockfd, (struct sockaddr*) &conn_addr, &addr_len)) == -1) {
			perror("accept failed");
			close(sockfd);
			
			return EXIT_FAILURE;
		}

		printf("%s:%u -> INADDR_ANY:%s Connected.\n", inet_ntoa(conn_addr.sin_addr), ntohs(conn_addr.sin_port), argv[1]);
		
		pid = fork();
		if(pid > 0) {
			close(connfd);
			continue;
		} else if (pid == 0) {
			int val = 1;

			while(1) {
				//read(connfd, buff, BUFFSIZE);
				//(*((int*)buff))++;
				write(connfd, &val, sizeof(int));
				val++;
				usleep(atoi(argv[2]));
			}

			close(connfd);
		} else {
			close(connfd);
			continue;
		}
	}

	close(sockfd);
	
	return 0;
}
