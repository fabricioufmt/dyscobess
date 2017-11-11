#include "dysco_center.h"

DyscoCenter::DyscoCenter() : Module() {
	bpf = new DyscoBPF();
}

DyscoTcpSession* DyscoCenter::get_supss(Ipv4* ip, Tcp* tcp) {
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

DyscoTcpSession* DyscoCenter::get_nextss(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();

	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second.nextss;
		it++;
	}
	
	return 0;
}

DyscoBPF::Filter* DyscoCenter::get_filter(bess::Packet* pkt) {
	return bpf->get_filter(pkt);
}

bool DyscoCenter::add_policy_rule(uint32_t priority, std::string exp, uint8_t* sc, uint32_t sc_len) {
	return bpf->add_filter(priority, exp, sc, sc_len);
}

bool DyscoCenter::add_mapping(Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
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
		cb.nextss.sip = cb.subss.dip;
		cb.nextss.dip = *((uint32_t*) cb.sc);
		cb.nextss.sport = (rand() % 1000 + 10000);
		cb.nextss.dport = (rand() % 1000 + 30000);
	}
	map.Insert(ss, cb);
	
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
