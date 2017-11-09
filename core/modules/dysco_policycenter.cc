#include "dysco_policycenter.h"

DyscoPolicyCenter::DyscoPolicyCenter() : Module() {

}

bool DyscoPolicyCenter::add(Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
	DyscoControlBlock cb;

	cb.subss.sip = ip->src.value();
	cb.subss.dip = ip->dst.value();
	cb.subss.sport = tcp->src_port.value();
	cb.subss.dport = tcp->dst_port.value();
	memcpy(&cb.supss, (DyscoTcpSession*)payload, sizeof(DyscoTcpSession));
	
	cb.sc = 0;
	cb.sc_len = 0;
	uint32_t sc_len = payload_len - sizeof(DyscoTcpSession) - sizeof(uint32);
	
	if(sc_len != 0) {
		cb.sc = (uint8_t*) malloc(sc_len);
		memcpy(cb.sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32), sc_len);
		cb.sc_len = sc_len;
	}

	return true;
}

ADD_MODULE(DyscoPolicyCenter, "dysco_policycenter", "Dysco core")
