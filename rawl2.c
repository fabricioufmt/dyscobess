#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#define MY_DEST_MAC0	0x00
#define MY_DEST_MAC1	0x00
#define MY_DEST_MAC2	0x00
#define MY_DEST_MAC3	0x00
#define MY_DEST_MAC4	0x00
#define MY_DEST_MAC5	0x00

#define DEFAULT_IF	"wlp2s0"
#define BUF_SIZ		1500

struct pseudo_header {
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;
  
	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
  
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
  
	return(answer);
}

struct tcp_session {
	unsigned int sip;
	unsigned int dip;
	unsigned short sport;
	unsigned short dport;
};


int main(int argc, char** argv) {
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header* eh = (struct ether_header*) sendbuf;
	struct iphdr* iph = (struct iphdr*) (sendbuf + sizeof(struct ether_header));
	struct tcphdr* tcph = (struct tcphdr*) (sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr));
	char* payload = (char*) (sendbuf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
	struct sockaddr_in sin;
	struct pseudo_header psh;
	struct sockaddr_ll socket_address;

	if(argc != 8) {
		printf("Usage: %s <iface> <MAC_dest> <IPs> <Ps> <IPd> <Pd> <TCP-flag>\n", argv[0]);
		exit(1);
	}

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, argv[1], IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, argv[1], IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	/*eh->ether_dhost[0] = argv[2][0];
	eh->ether_dhost[1] = argv[2][1];
	eh->ether_dhost[2] = argv[2][2];
	eh->ether_dhost[3] = argv[2][3];
	eh->ether_dhost[4] = argv[2][4];
	eh->ether_dhost[5] = argv[2][5];*/
	eh->ether_dhost[0] = 0;
	eh->ether_dhost[1] = 0;
	eh->ether_dhost[2] = 0;
	eh->ether_dhost[3] = 0;
	eh->ether_dhost[4] = 0;
	eh->ether_dhost[5] = 0;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);
	tx_len += sizeof(struct ether_header);

	/* Payload */
	struct tcp_session ss;
	ss.sip = inet_addr("10.0.1.1");
	ss.dip = inet_addr("200.200.200.65");
	ss.sport = 12345;
	ss.dport = 8080;
	unsigned int sc1 = inet_addr("192.168.1.254");
	unsigned int sc2 = inet_addr("192.168.3.50");
	unsigned int sc3 = inet_addr("200.200.200.250");
	unsigned int sc4 = inet_addr("200.200.200.65");
	memcpy(payload, &ss, sizeof(struct tcp_session));
	memcpy(payload + sizeof(struct tcp_session), &sc1, sizeof(unsigned int));
	memcpy(payload + sizeof(struct tcp_session) + sizeof(unsigned int), &sc2, sizeof(unsigned int));
	memcpy(payload + sizeof(struct tcp_session) + sizeof(unsigned int) + sizeof(unsigned int), &sc3, sizeof(unsigned int));
	memcpy(payload + sizeof(struct tcp_session) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int), &sc4, sizeof(unsigned int));
	int payload_len = sizeof(struct tcp_session) + (4 * sizeof(unsigned int));
	tx_len += payload_len;
	
	/* IP header */
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htonl(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
	iph->id = htonl (54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(argv[3]);
	iph->daddr = inet_addr(argv[5]);
	iph->check = csum((unsigned short*) (sendbuf + sizeof(struct ether_header)),
			  sizeof(struct iphdr) + sizeof(struct tcphdr));
	tx_len += sizeof(struct iphdr);
	
	/* TCP header */
	tcph->source = htons(atoi(argv[4]));
	tcph->dest = htons(atoi(argv[6]));
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	switch(atoi(argv[7])) {
	case 1:
		tcph->fin = 1;
		break;
	case 2:
		tcph->syn = 1;
		break;
	case 4:
		tcph->rst = 1;
		break;
	case 8:
		tcph->psh = 1;
		break;
	case 16:
		tcph->ack = 1;
		break;
	case 24:
		tcph->ack = 1;
		tcph->psh = 1;
		break;
    
	}
	tcph->window = htons(5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tx_len += sizeof(struct tcphdr);

	/* TCP Checksum */
	psh.source_address = inet_addr(argv[3]);
	psh.dest_address = inet_addr(argv[5]);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + payload_len);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_len;
	char* pseudogram = malloc(psize);
     
	memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + payload_len);
     
	tcph->check = csum((unsigned short*) pseudogram, psize);

	
	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	/*socket_address.sll_addr[0] = argv[2][0];
	socket_address.sll_addr[1] = argv[2][1];
	socket_address.sll_addr[2] = argv[2][2];
	socket_address.sll_addr[3] = argv[2][3];
	socket_address.sll_addr[4] = argv[2][4];
	socket_address.sll_addr[5] = argv[2][5];*/
	socket_address.sll_addr[0] = 0;
	socket_address.sll_addr[1] = 0;
	socket_address.sll_addr[2] = 0;
	socket_address.sll_addr[3] = 0;
	socket_address.sll_addr[4] = 0;
	socket_address.sll_addr[5] = 0;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}
