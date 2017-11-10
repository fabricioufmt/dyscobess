#include "dysco_center.h"

DyscoCenter::DyscoCenter() : Module() {

}

DyscoTcpSession* DyscoCenter::get_session(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();

	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second.supss;
		it++;
	}
	
	return 0;
}

DyscoControlBlock* DyscoCenter::get_controlblock(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();

	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second;
		it++;
	}

	return 0;
}

bool DyscoCenter::add(Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
	DyscoControlBlock cb;
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();
	cb.subss = ss;
	memcpy(&cb.supss, (DyscoTcpSession*)payload, sizeof(DyscoTcpSession));
	
	cb.sc = 0;
	cb.sc_len = 0;
	uint32_t sc_len = payload_len - sizeof(DyscoTcpSession) - sizeof(uint32_t);
	
	if(sc_len != 0) {
		cb.sc = (uint8_t*) malloc(sc_len);
		memcpy(cb.sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), sc_len);
		cb.sc_len = sc_len;
	}
	map.Insert(ss, cb);
	
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
