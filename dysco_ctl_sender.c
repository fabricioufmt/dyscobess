#include <stdio.h>
#include <errno.h>
#include <net/if.h>
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
	uint32_t sc1;
	uint32_t sc2;
	uint32_t sc3;
};

int main(int argc, char** argv) {
	int n;
	int sockfd;
	int connfd;
	socklen_t addr_len;
	unsigned char buff[BUFSIZE];
	struct sockaddr_in serv_addr;

	//Dysco
	int sc_len;
	uint32_t* sc;
	struct tcp_session* ss;
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		perror("socket failed");

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(INADDR_ANY);
	serv_addr.sin_port = htons(PORT);

	if(connect(sockfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1)
		perror("connect failed");

	memset(buff, 0, BUFSIZE);

	ss = (struct tcp_session*)(buff);
	ss->sip = inet_addr("1.2.3.4");
	ss->dip = inet_addr("5.6.7.8");
	ss->sport = htons(9876);
	ss->dport = htons(50321);
	ss->sc1 = inet_addr("9.10.11.12");
	ss->sc2 = inet_addr("13.14.15.16");
	ss->sc3 = inet_addr("17.18.19.20");
	
	n = write(sockfd, buff, sizeof(struct tcp_session));

	close(sockfd);

	return 0;
}
