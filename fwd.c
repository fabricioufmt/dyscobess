#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
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

int main(int argc, char** argv) {
	int i;
	int n;
	int sockfd;
	int saddr_size;
	char buffer[65535];
	struct sockaddr saddr;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	if(argc != 2) {
		printf("Usage: %s <iface>\n", argv[0]);
		exit(1);
	}

	
	
	i = 0;
	//sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd < 0)
		return -1;

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
	
	while(1) {
		saddr_size = sizeof(saddr);
		memset(buffer, 0, sizeof(buffer));
		
		n = recvfrom(sockfd, buffer, sizeof(buffer), 0, &saddr, (socklen_t*) &saddr_size);
		if(n < 0) {
			perror("recvfrom < 0 byte");
			continue;
		}
		
		printf("Packet counter: %d.\n", i++);

		socket_address.sll_ifindex = if_idx.ifr_ifindex;
		socket_address.sll_halen = ETH_ALEN;
		socket_address.sll_addr[0] = 0;
		socket_address.sll_addr[1] = 0;
		socket_address.sll_addr[2] = 0;
		socket_address.sll_addr[3] = 0;
		socket_address.sll_addr[4] = 0;
		socket_address.sll_addr[5] = 0;
		
		//n = sendto(sockfd, buffer, n, 0, &saddr, (socklen_t) saddr_size);
		n = sendto(sockfd, buffer, n, 0, (struct sockaddr*) &socket_address, sizeof(struct sockaddr_ll));
		if(n < 0) {
			perror("sendto < 0 byte");
			continue;
		}
	}

	return 0;
}
