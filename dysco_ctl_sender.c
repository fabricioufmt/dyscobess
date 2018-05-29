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
#define PORT 2017
#define BUFSIZE 1500

struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
};

struct reconfig_message {
	struct tcp_session	super;
	struct tcp_session	leftSS;
	struct tcp_session	rightSS;
	uint32_t		leftA;
	uint32_t		rightA;
	
        uint16_t		sport;
	uint16_t		dport;
	
	uint32_t		leftIseq;
	uint32_t		leftIack;
	
	uint32_t		rightIseq;
	uint32_t		rightIack;
	
	uint32_t		seqCutoff;
	
	uint32_t		leftIts;
	uint32_t		leftItsr;
	
	uint16_t		leftIws;
	uint16_t		leftIwsr;

	uint16_t		sackOk;
	
	uint16_t		semantic;
	
	uint32_t		srcMB;
	uint32_t		dstMB;
} __attribute__((packed));

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
	struct reconfig_message* cmsg;

	if(argc < 4) {
		fprintf(stderr, "Usage: %s <sup:src_port><rightSS:src_port> <sc1> <sc2> <...>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	sc_len = argc - 3;
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		perror("socket failed");

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(PORT);

	if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		perror("connect failed");

	tx_len = sizeof(struct reconfig_message) + 4 + sc_len * sizeof(uint32_t); //+4 for Service Chain length (uint32)
	buff = malloc(tx_len);
	memset(buff, 0, tx_len);

	cmsg = (struct reconfig_message*)(buff);
	cmsg->super.sip = inet_addr("10.0.2.1");
	cmsg->super.dip = inet_addr("10.0.10.2");
	cmsg->super.sport = htons(atoi(argv[1]));
	cmsg->super.dport = htons(5001);

	cmsg->leftSS.sip = inet_addr("10.0.10.1");
	cmsg->leftSS.dip = inet_addr("10.0.10.2");
	cmsg->leftSS.sport = htons(atoi(argv[1]));
	cmsg->leftSS.dport = htons(5001);
	
	cmsg->rightSS.sip = inet_addr("10.0.3.2");
	cmsg->rightSS.dip = inet_addr("10.0.3.1");
	cmsg->rightSS.sport = htons(atoi(argv[2]));
	cmsg->rightSS.dport = htons(5001);
	
	//cmsg->leftSS = cmsg->rightSS = cmsg->super;

	uint32_t sclen = htonl(sc_len);
	memcpy(buff + sizeof(struct reconfig_message), &sclen, sizeof(uint32_t));
	sc = (uint32_t*)(buff + sizeof(struct reconfig_message) + sizeof(uint32_t));
	for(i = 0; i < sc_len; i++)
		sc[i] = inet_addr(argv[3 + i]);

	cmsg->leftA = inet_addr("10.0.2.1");
	cmsg->rightA = sc[sc_len - 1];
	
	fprintf(stdout, "Sending data (cmsg + sc) with %d service chain elements with ", sc_len);
	n = write(sockfd, buff, tx_len);

	if(n != -1)
		fprintf(stdout, "%d bytes as payload... OK\n", n);
	else
		fprintf(stdout, "ERROR...\n");
	
	close(sockfd);

	return 0;
}
