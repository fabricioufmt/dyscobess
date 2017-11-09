#include "dysco_policycenter.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;

DyscoPolicyCenter::DyscoPolicyCenter() : Module() {

}

bool DyscoPolicyCenter::add(Ipv4* ip, Tcp* tcp, uint8_t* payload, int payload_len) {
	return true;
}

ADD_MODULE(DyscoPolicyCenter, "dysco_policycenter", "Dysco core")
