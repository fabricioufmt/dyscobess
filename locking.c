#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>

#define MIN_ARGC 11
#define BUFSIZE 2048
#define OPT_KIND 254
#define OPT_LENGTH 4

struct tcp_session {
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;
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

	uint8_t			lhop;
	uint8_t			rhop;
	uint16_t		padding;
} __attribute__((packed));

struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t tcp_length;
};

struct tcpopt {
	uint8_t kind;
	uint8_t len;
	uint16_t padding;
};

/*
 * This application implements locking protocol for Dysco
 * @args= <SIP> <SP> <DIP> <DP> <SIP> <SP> <DIP> <DP> <left_hop> <right_hop> <service chain>
 */

uint16_t csum(uint16_t*, uint32_t);
void create_datagram(struct iphdr*, uint32_t, uint32_t, uint32_t);
void create_segment(struct iphdr*, struct tcphdr*, uint16_t, uint16_t, struct tcpopt*, uint8_t, uint8_t, struct reconfig_message*, uint32_t, uint32_t*);

int main(int argc, char** argv) {
	//Variables
	int32_t i;
	int32_t n;
	int32_t on;
	int32_t sockfd;
	uint32_t sc_len;
	uint32_t packet_len;
	struct iphdr* iph;
	struct tcphdr* tcph;
	struct tcpopt* tcpo;
	struct sockaddr_in sin;
	uint8_t buffer[BUFSIZE];
	struct reconfig_message* cmsg;
	
	if(argc < MIN_ARGC) {
		fprintf(stderr, "Usage: %s <SIP> <SP> <DIP> <DP> <SIP> <SP> <DIP> <DP> <left_hop> <right_hop> [service chain].\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		fprintf(stderr, "ERROR: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	on = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		fprintf(stderr, "ERROR: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[4]));
	sin.sin_addr.s_addr = inet_addr(argv[3]);

	memset(buffer, 0, BUFSIZE);
	iph = (struct iphdr*) (buffer);
	packet_len = sizeof(struct iphdr);
	tcph = (struct tcphdr*) (buffer + packet_len);
	packet_len += sizeof(struct tcphdr);
	tcpo = (struct tcpopt*) (buffer + packet_len);
	packet_len += OPT_LENGTH;

	cmsg = (struct reconfig_message*) (buffer + packet_len);
	packet_len += sizeof(struct reconfig_message);
	
	sc_len = argc - MIN_ARGC;
	uint32_t* sc = (uint32_t*) malloc(sc_len * 4);
	for(i = 0; i < sc_len; i++)
		sc[i] = inet_addr(argv[MIN_ARGC + i]);

	memcpy(buffer + packet_len, sc, sc_len * sizeof(uint32_t));
	packet_len += sc_len * sizeof(uint32_t);

	cmsg->rightSS.sip = inet_addr(argv[5]);
	cmsg->rightSS.dip = inet_addr(argv[7]);
	cmsg->rightSS.sport = htons(atoi(argv[6]));
	cmsg->rightSS.dport = htons(atoi(argv[8]));
	
	create_datagram(iph, inet_addr(argv[1]), inet_addr(argv[3]), packet_len);
	create_segment(iph, tcph, htons(atoi(argv[2])), htons(atoi(argv[4])), tcpo, atoi(argv[9]), atoi(argv[10]), cmsg, sc_len, sc);
	
	if((n = sendto(sockfd, buffer, ntohs(iph->tot_len), 0, (struct sockaddr*) &sin, sizeof(sin))) < 0) {
		fprintf(stderr, "ERROR: %s.\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return 0;
}

void create_datagram(struct iphdr* iph, uint32_t sip, uint32_t dip, uint32_t packet_len) {
	// Construct the IP datagram
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(packet_len);
	iph->id = htons(rand());
	iph->frag_off = 0;
	iph->ttl = 32;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = sip;
	iph->daddr = dip;
	iph->check = csum((uint16_t*) iph, iph->ihl << 2);
}

void create_segment(struct iphdr* iph, struct tcphdr* tcph, uint16_t sport, uint16_t dport, struct tcpopt* tcpo, uint8_t lhop, uint8_t rhop, struct reconfig_message* cmsg, uint32_t sc_len, uint32_t* sc) {
	// Construct the TCP segment 
	tcph->source = sport;
	tcph->dest = dport;
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = 5 + (OPT_LENGTH >> 2);
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	//Construct the TCP Option
	tcpo->kind = OPT_KIND;
	tcpo->len = OPT_LENGTH;
	tcpo->padding = lhop;
	tcpo->padding <<= 8;
	tcpo->padding |= rhop;

	cmsg->lhop = lhop;
	cmsg->rhop = rhop;

	//Construct the pseudo header
	struct pseudo_header psh;
	psh.source_address = iph->saddr;
	psh.dest_address = iph->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons((tcph->doff << 2) + sizeof(struct reconfig_message) + sc_len * sizeof(uint32_t));
	uint32_t size = sizeof(struct pseudo_header) + (tcph->doff << 2) + sizeof(struct reconfig_message) + sc_len * sizeof(uint32_t);
	uint8_t* buff = malloc(size);

	memcpy(buff, &psh, sizeof(struct pseudo_header));
	memcpy(buff + sizeof(struct pseudo_header), tcph, tcph->doff << 2);
	memcpy(buff + sizeof(struct pseudo_header) + (tcph->doff << 2), cmsg, sizeof(struct reconfig_message));
	memcpy(buff + sizeof(struct pseudo_header) + (tcph->doff << 2) + sizeof(struct reconfig_message), sc, sc_len * sizeof(uint32_t));
	tcph->check = csum((uint16_t*) buff, size);
}

uint16_t csum(uint16_t *ptr, uint32_t nbytes) {
	register long sum;
	uint16_t oddbyte;
  
	sum = 0;
	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	
	if(nbytes == 1) {
		oddbyte = 0;
		*((uint8_t*) &oddbyte) = *(uint8_t*)ptr;
		sum += oddbyte;
	}
  
	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
  
	return (int16_t) ~sum;
}
