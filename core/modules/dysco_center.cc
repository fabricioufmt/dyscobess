#include "dysco_center.h"

DyscoCenter::DyscoCenter() : Module() {

}

DyscoTcpSession* DyscoCenter::get_session(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();

	auto* it = map.Find(ss);
	if(it == nullptr)
		return 0;

	DyscoControlBlock node = it->second;

	return &(node.supss);
}

bool DyscoCenter::add(Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
	DyscoControlBlock cb;

	cb.subss.sip = ip->src.value();
	cb.subss.dip = ip->dst.value();
	cb.subss.sport = tcp->src_port.value();
	cb.subss.dport = tcp->dst_port.value();
	memcpy(&cb.supss, (DyscoTcpSession*)payload, sizeof(DyscoTcpSession));
	
	cb.sc = 0;
	cb.sc_len = 0;
	uint32_t sc_len = payload_len - sizeof(DyscoTcpSession) - sizeof(uint32_t);
	
	if(sc_len != 0) {
		cb.sc = (uint8_t*) malloc(sc_len);
		memcpy(cb.sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), sc_len);
		cb.sc_len = sc_len;
	}

	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
