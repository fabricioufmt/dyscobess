#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
	if(argc != 6) {
		printf("Usage: %s <IPs> <Ps> <IPd> <Pd> <TCP-flag>\n", argv[0]);
		exit(1);
	}
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  
	if(s == -1) {
		perror("Failed to create socket");
		exit(1);
	}
     
	char datagram[4096], source_ip[32], *data, *pseudogram;
     
	memset (datagram, 0, 4096);
  
	struct iphdr* iph = (struct iphdr*) datagram;
	struct tcphdr* tcph = (struct tcphdr*) (datagram + sizeof(struct ip));
	struct sockaddr_in sin;
	struct pseudo_header psh;
     
	data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct tcp_session ss;
	ss.sip = inet_addr("10.0.1.1");
	ss.dip = inet_addr("200.200.200.65");
	ss.sport = 12345;
	ss.dport = 8080;
	unsigned int sc1 = inet_addr("192.168.1.254");
	unsigned int sc2 = inet_addr("192.168.3.50");
	unsigned int sc3 = inet_addr("200.200.200.250");
	unsigned int sc4 = inet_addr("200.200.200.65");
	memcpy(data, &ss, sizeof(struct tcp_session));
	memcpy(data + sizeof(struct tcp_session), &sc1, sizeof(unsigned int));
	memcpy(data + sizeof(struct tcp_session) + sizeof(unsigned int), &sc2, sizeof(unsigned int));
	memcpy(data + sizeof(struct tcp_session) + sizeof(unsigned int) + sizeof(unsigned int), &sc3, sizeof(unsigned int));
	memcpy(data + sizeof(struct tcp_session) + sizeof(unsigned int) + sizeof(unsigned int) + sizeof(unsigned int), &sc4, sizeof(unsigned int));
     
	strcpy(source_ip, argv[1]);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[4]));
	sin.sin_addr.s_addr = inet_addr(argv[3]);
     
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);
	iph->id = htonl (54321); //Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;      //Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
	iph->daddr = sin.sin_addr.s_addr;
     
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
     
	//TCP Header
	tcph->source = htons(atoi(argv[2]));
	//tcph->dest = htons(81);
	tcph->dest = sin.sin_port;
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;  //tcp header size
	tcph->fin=0;
	tcph->syn=0;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	switch(atoi(argv[5])) {
	case 1:
		tcph->fin=1;
		break;
	case 2:
		tcph->syn=1;
		break;
	case 4:
		tcph->rst=1;
		break;
	case 8:
		tcph->psh=1;
		break;
	case 16:
		tcph->ack=1;
		break;
	case 24:
		tcph->ack=1;
		tcph->psh=1;
		break;
    
	}
	tcph->window = htons (5840);
	tcph->check = 0;
	tcph->urg_ptr = 0;
     
	//Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );
     
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
	pseudogram = malloc(psize);
     
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(data));
     
	tcph->check = csum( (unsigned short*) pseudogram , psize);
     
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
     
	if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
		perror("Error setting IP_HDRINCL");
		exit(0);
	}
  
	int i;
	//loop if you want to flood :)
	while(i < 1) {
		if(sendto(s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
			perror("sendto failed");
		} else {
			printf ("Packet Send. Length : %d \n" , iph->tot_len);
		}
		i++;
	}
  
	return 0;
}
