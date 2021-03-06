#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#include <netdb.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define IFACE "lo"
#define SEED 1024
#define LISTENQ 50
#define BUFSIZE 1500

#define BIT_LEN 32
#define IP_BYTE_LEN 4
#define BUFFER_SIZE 4096
#define UEXIT_FAILURE 0

#define SUPER_PORT 6998
#define LEFT_RIGHT_PORT 6999
char super[BUFSIZE];
char left_right[BUFSIZE];

enum {
	// Locking protocol
	DYSCO_REQUEST_LOCK = 1,
	DYSCO_ACK_LOCK,
	DYSCO_NACK_LOCK,
	
	// Reconfiguration
	DYSCO_SYN,
	DYSCO_SYN_ACK,
	DYSCO_ACK,
	DYSCO_FIN,
	DYSCO_FIN_ACK,
	
	// Management
	DYSCO_POLICY,
	DYSCO_REM_POLICY,
	DYSCO_CLEAR,
	DYSCO_CLEAR_ALL,
	DYSCO_BUFFER_PACKET,
	DYSCO_TCP_SPLICE,
	DYSCO_COPY_STATE,
	DYSCO_PUT_STATE,
	DYSCO_STATE_TRANSFERRED,
	DYSCO_ACK_ACK,
	DYSCO_GET_MAPPING,
	DYSCO_GET_REC_TIME
};

struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
};

struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t  placeholder;
	uint8_t  protocol;
	uint16_t tcp_length;
};

struct reconfig_message {
	struct tcp_session      my_sub;
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

char* printIP(uint32_t ip);
char* printSS(struct tcp_session ss);
unsigned short csum(unsigned short*, uint32_t);
uint32_t get_srcip(uint32_t*, int32_t*);
void create_message_reconfig(struct reconfig_message*, uint32_t, uint32_t*);

static void* receive_super(void*);
static void* receive_left_right(void*);

int main(int argc, char** argv) {
	int n;
	int sockfd;
	int connfd;
	socklen_t addr_len;
	unsigned char buff[BUFSIZE];
	struct sockaddr_in serv_addr;
	struct sockaddr_in conn_addr;

	//Dysco
	int sc_len;
	uint32_t* sc;

	if(argc != 2) {
		fprintf(stderr, "Usage: %s <port>.\n", argv[0]);
		return -1;
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

	pthread_t tid1, tid2;
	pthread_create(&tid1, 0, receive_super, 0);
	pthread_create(&tid2, 0, receive_left_right, 0);

	int total_n = 0;
	srand(SEED);
	while(1) {
		memset(&conn_addr, 0, sizeof(struct sockaddr_in));
		if((connfd = accept(sockfd, (struct sockaddr*) &conn_addr, &addr_len)) == -1) {
			perror("accept failed");
			return EXIT_FAILURE;
		}

		fprintf(stdout, "Client is connected.\n");
		
		memset(buff, 0, BUFSIZE);
		if((n = read(connfd, buff, BUFSIZE)) == -1) {
			fprintf(stderr, "read error: %s.\n", strerror(errno));
			close(connfd);
			continue;
		}

		fprintf(stdout, "Received %d bytes\n", n);
		
		total_n += n;
		while(total_n < sizeof(struct reconfig_message) + sizeof(uint32_t)) {
			n = read(connfd, buff + total_n, BUFSIZE - total_n);
			if(n < 1)
				break;
			
			fprintf(stdout, "Received %d bytes\n", n);
			total_n += n;
		}

		sc_len = ntohl(*((int*)(buff + sizeof(struct reconfig_message))));
		sc = (uint32_t*)(buff + sizeof(struct reconfig_message) + sizeof(uint32_t));

		//NOTE: at least one element on sc list
		if(sc_len < 1) {
			fprintf(stderr, "sc_len = 0.\n");
			close(connfd);
			continue;
		}

		create_message_reconfig((struct reconfig_message*) buff, sc_len, sc);
		close(connfd);
	}

	close(sockfd);
	
	return 0;
}

static void* receive_super(void* arg) {
	int n;
	int sockfd1;
	int connfd1;
	socklen_t addr_len;
	unsigned char buff[BUFSIZE];
	struct sockaddr_in serv_addr;
	
	if((sockfd1 = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket failed");
		exit(-1);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(SUPER_PORT);

	if(bind(sockfd1, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("bind failed");
		exit(-1);
	}

	if(listen(sockfd1, LISTENQ) == -1) {
		perror("listen failed");
		exit(-1);
	}

	if((connfd1 = accept(sockfd1, 0, &addr_len)) == -1) {
		perror("accept failed");
		exit(-1);
	}
		
	memset(super, 0, BUFSIZE);
	if((n = read(connfd1, super, BUFSIZE)) == -1) {
		fprintf(stderr, "read error: %s.\n", strerror(errno));
		close(connfd1);
		exit(-1);
	}

	struct tcp_session* ss = (struct tcp_session*) super;

	printf("Super: %s\n", printSS(*ss));
	
	close(connfd1);
	close(sockfd1);
}

static void* receive_left_right(void* arg) {
	int n;
	int total_n;
	int sockfd2;
	int connfd2;
	socklen_t addr_len;
	unsigned char buff[BUFSIZE];
	struct sockaddr_in serv_addr;
	
	if((sockfd2 = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket failed");
		exit(-1);
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(LEFT_RIGHT_PORT);

	if(bind(sockfd2, (struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
		perror("bind failed");
		exit(-1);
	}

	if(listen(sockfd2, LISTENQ) == -1) {
		perror("listen failed");
		exit(-1);
	}

	if((connfd2 = accept(sockfd2, 0, &addr_len)) == -1) {
		perror("accept failed");
		exit(-1);
	}
		
	memset(left_right, 0, BUFSIZE);
	if((n = read(connfd2, left_right, BUFSIZE)) == -1) {
		fprintf(stderr, "read error: %s.\n", strerror(errno));
		close(connfd2);
		exit(-1);
	}

	total_n = n;
	while(total_n < 24) {
		if((n = read(connfd2, left_right + total_n, BUFSIZE - total_n)) == -1) {
			fprintf(stderr, "read error: %s.\n", strerror(errno));
			close(connfd2);
			exit(-1);
		}

		total_n += n;
	}

	struct tcp_session* leftSS = (struct tcp_session*) left_right;
	struct tcp_session* rightSS = (struct tcp_session*) (left_right + sizeof(struct tcp_session));

	printf("LeftSS: %s\n", printSS(*leftSS));
	printf("RightSS: %s\n", printSS(*rightSS));

	close(connfd2);
	close(sockfd2);
}

void create_message_reconfig(struct reconfig_message* rmsg, uint32_t sc_len, uint32_t* sc) {
	int on;
	int32_t ifindex;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct reconfig_message* cmsg;
	uint32_t tx_len;
	uint32_t sockfd;
	uint32_t payload_len;
	struct pseudo_header psh;
	struct sockaddr_ll sock_addr;
	unsigned char sendbuf[BUFSIZ];

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		perror("socket");
	}
	
	on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		perror("setsockopt failed");
		exit(EXIT_FAILURE);
	}
	
	memset(sendbuf, 0, BUFSIZ);
	iph = (struct iphdr*) (sendbuf);
	tcph = (struct tcphdr*) (sendbuf + sizeof(struct iphdr));
	memcpy(sendbuf + sizeof(struct iphdr) + sizeof(struct tcphdr), rmsg, sizeof(struct reconfig_message));
	cmsg = (struct reconfig_message*) (sendbuf + sizeof(struct iphdr) + sizeof(struct tcphdr));
	
	tx_len = 0;
	//Last byte for Reconfiguration tag (+1)
	payload_len = sizeof(struct reconfig_message) + sc_len * sizeof(uint32_t) + 1;
	
	// Construct the IP datagram
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
	iph->id = htons(rand());
	iph->frag_off = 0;
	iph->ttl = 32;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	//iph->saddr = get_srcip(&rmsg->rightA, &ifindex); //or rmsg->leftA; ?
	//iph->daddr = rmsg->rightA;
	iph->saddr = get_srcip(&sc[0], &ifindex);

	//TEST
	cmsg->leftA = iph->saddr;
	cmsg->rightA = inet_addr("10.0.4.2");

	if(cmsg->super.sip == 0)
		memcpy(&cmsg->super, (struct tcp_session*) super, sizeof(struct tcp_session));
	if(cmsg->leftSS.sip == 0)
		memcpy(&cmsg->leftSS, (struct tcp_session*) left_right, sizeof(struct tcp_session));
	if(cmsg->rightSS.sip == 0)
		memcpy(&cmsg->rightSS, (struct tcp_session*) (left_right + sizeof(struct tcp_session)), sizeof(struct tcp_session));

	iph->daddr = sc[0];
	iph->check = csum((unsigned short*) sendbuf, sizeof(struct iphdr) + sizeof(struct tcphdr));
	tx_len += sizeof(struct iphdr); //IP does not have Option field.
	
	// Construct the TCP segment 
	tcph->source = htons(40000 + rand() % 1000);
	tcph->dest = htons(50000 + rand() % 1000);
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tx_len += sizeof(struct tcphdr); //TCP does not have Option field

	tx_len += sizeof(struct reconfig_message);
	
	cmsg->my_sub.sip = iph->saddr;
	cmsg->my_sub.dip = iph->daddr;
	cmsg->my_sub.sport = tcph->source;
	cmsg->my_sub.dport = tcph->dest;
	
	// Construct Service Chain
	memcpy(sendbuf + tx_len, sc, sc_len * sizeof(uint32_t));
	tx_len += sc_len * sizeof(uint32_t);

	// Insert Reconfig Tag
	sendbuf[tx_len] = 0xFF;
	tx_len++;
	
	// Construct the Pseudo Header
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);

	uint32_t psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
	uint8_t* pgram = malloc(psize);

	memcpy(pgram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy(pgram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
	memcpy(pgram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), cmsg, sizeof(struct reconfig_message));
	memcpy(pgram + sizeof(struct pseudo_header) + sizeof(struct tcphdr) + sizeof(struct reconfig_message), sc, sc_len * sizeof(uint32_t));
	pgram[psize - 1] = 0xFF;

	tcph->check = csum((unsigned short*) pgram, psize);
	sock_addr.sll_ifindex = ifindex;

	fprintf(stdout, "with %d bytes... ", tx_len);
	if(sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*) &sock_addr, sizeof(struct sockaddr_ll)) < 0)
		perror("send failed");
	
	fprintf(stdout, "OK.\n");
}

uint32_t get_srcip(uint32_t* destip, int32_t* ifindex) {
	int n;
	int sockfd;
	int msgseq;
	int rt_len;
	int msg_len;
	
	char* ptr;
	char buff[BUFFER_SIZE];
	char iface[IF_NAMESIZE];
	char hostip[NI_MAXHOST];
	char msgbuf[BUFFER_SIZE];

	struct rtmsg* entry;
	struct rtattr* rt;
	struct rtattr* rta;
	struct nlmsghdr* nlh;
	struct nlmsghdr* nlmsg;
	struct timeval tv;
	struct ifaddrs* ifa;
	struct ifaddrs* ifaddr;
	
	struct {
		struct nlmsghdr nl;
		struct rtmsg rt;
		char buf[BUFFER_SIZE];
	} req;

	msgseq = 0;
	ptr = buff;
	msg_len = 0;
	memset(msgbuf, 0, BUFFER_SIZE);
	memset(buff, 0, BUFFER_SIZE);
	nlmsg = &req.nl;

	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE;
	nlmsg->nlmsg_flags = NLM_F_REQUEST;
	nlmsg->nlmsg_seq = msgseq++;
	nlmsg->nlmsg_pid = getpid();

	rta = (struct rtattr*) req.buf;
        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(IP_BYTE_LEN);
        memcpy(RTA_DATA(rta), destip, IP_BYTE_LEN);
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(rta->rta_len);

	req.rt.rtm_family = AF_INET;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_type = RTN_UNICAST;
	req.rt.rtm_dst_len = 32;
	
	if((sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		perror("socket failed");
		return UEXIT_FAILURE;
	}
	
	tv.tv_sec = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*) &tv, sizeof(struct timeval));

	if(send(sockfd, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		perror("send failed");
		return UEXIT_FAILURE;
	}

	do {
		n = recv(sockfd, ptr, sizeof(buff) - msg_len, 0);
		if(n < 0) {
			perror("Error in recv");
			return UEXIT_FAILURE;
		}
		
		nlh = (struct nlmsghdr*) ptr;
		
		if((NLMSG_OK(nlmsg, n) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
			perror("Error in received packet");
			return UEXIT_FAILURE;
		}
		
		if(nlh->nlmsg_type == NLMSG_DONE)
			break;
		else {
			ptr += n;
			msg_len += n;
		}
		
		if((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0)
			break;
		
	} while((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

	if(getifaddrs(&ifaddr) == -1) {
		perror("Error in getifaddrs");
		return UEXIT_FAILURE;
	}
	
	for(; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n)) {
		entry = (struct rtmsg*) NLMSG_DATA(nlh);
		
		if(entry->rtm_table != RT_TABLE_MAIN)
			continue;
		
		rt = (struct rtattr*) RTM_RTA(entry);
		rt_len = RTM_PAYLOAD(nlh);
		
		for(; RTA_OK(rt, rt_len); rt = RTA_NEXT(rt, rt_len)) {
			switch(rt->rta_type) {
			case RTA_OIF:
				if_indextoname(*(int*)RTA_DATA(rt), iface);
				for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
					if(ifa->ifa_addr == NULL)
						continue;

					if(strcmp(iface, ifa->ifa_name) != 0) 
						continue;

					if(ifa->ifa_addr->sa_family != AF_INET)
						continue;

					*ifindex = *(int*)RTA_DATA(rt);
					getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hostip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				}
				
				break;
			}
		
		}
		
		if(hostip[0]) {
			freeifaddrs(ifaddr);
			close(sockfd);
			fprintf(stdout, "Sending through %s interface with %s as source address ", iface, hostip);
			return inet_addr(hostip);			
		}	
	}

	freeifaddrs(ifaddr);
	close(sockfd);
	
	return UEXIT_FAILURE;
}

unsigned short csum(unsigned short* ptr, uint32_t nbytes) {
	register long sum;
	unsigned short oddbyte;
  
	sum = 0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	
	if(nbytes == 1) {
		oddbyte = 0;
		*((unsigned char*) &oddbyte) = *(unsigned char*)ptr;
		sum += oddbyte;
	}
  
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
  
	return (short) ~sum;
}

char* printIP(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

char* printSS(struct tcp_session ss) {
	char* buf = (char*) malloc(64);
	sprintf(buf, "%s:%u -> %s:%u",
		printIP(ntohl(ss.sip)), ntohs(ss.sport),
		printIP(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}
