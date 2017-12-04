#ifndef __DYSCO_UTILS_H_
#define __DYSCO_UTILS_H_

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

bool isIP(Ethernet* eth) {
	return eth->ether_type == Ethernet::Type::kIpv4;
}

bool isTCP(Ipv4* ip) {
	return ip->protocol == Ipv4::Proto::kTcp;
}

bool isTCPSYN(Tcp* tcp) {
	return tcp->flags == Tcp::Flag::kSyn;
}

bool hasPayload(Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;

	return ip->length.value() - ip_hlen - tcp_hlen;
}

#endif __DYSCO_UTILS_H_
