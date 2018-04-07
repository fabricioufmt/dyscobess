#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#define IFACE "lo"
#define LISTENQ 50
#define PORT 50123
#define BUFSIZE 1500

struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
};

int main(int argc, char** argv) {
	int i;
	int n;
	int sockfd;
	int connfd;
	int tx_len;
	socklen_t addr_len;
	unsigned char* buff;
	struct sockaddr_in serv_addr;

	//Dysco
	int sc_len;
	uint32_t* sc;
	struct tcp_session* ss;

	if(argc < 5) {
		fprintf(stderr, "Usage: %s <IPs><Ps><IPd><Pd> <sc1> <sc2> <...>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sc_len = argc - 5;
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		perror("socket failed");

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(PORT);

	if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		perror("connect failed");

	tx_len = sizeof(struct tcp_session) + sc_len * sizeof(uint32_t);
	buff = malloc(tx_len);
	memset(buff, 0, tx_len);

	ss = (struct tcp_session*)(buff);
	ss->sip = inet_addr(argv[1]);
	ss->dip = inet_addr(argv[3]);
	ss->sport = htons(atoi(argv[2]));
	ss->dport = htons(atoi(argv[4]));

	sc = (uint32_t*)(buff + sizeof(struct tcp_session));
	for(i = 0; i < sc_len; i++)
		sc[i] = inet_addr(argv[5 + i]);
	
	n = write(sockfd, buff, tx_len);

	close(sockfd);

	return 0;
}
