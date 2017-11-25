#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

int main(int argc, char** argv) {
	int i;
	int n;
	int sockfd;
	int saddr_size;
	char buffer[65535];
	struct sockaddr saddr;

	i = 0;
	//sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd < 0)
		return -1;

	while(1) {
		saddr_size = sizeof(saddr);
		memset(buffer, 0, sizeof(buffer));
		
		n = recvfrom(sockfd, buffer, sizeof(buffer), 0, &saddr, (socklen_t*) &saddr_size);
		if(n < 0) {
			perror("recvfrom < 0 byte");
			continue;
		}
		
		printf("Packet counter: %d.\n", i++);
		n = sendto(sockfd, buffer, n, 0, &saddr, (socklen_t) saddr_size);
		if(n < 0) {
			perror("sendto < 0 byte");
			continue;
		}
	}

	return 0;
}
