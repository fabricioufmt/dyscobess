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

	//TODO: check with Ronaldo, if this is really necessary
	char buf[256];
	char ipsrc[INET_ADDRSTRLEN];
	char ipdst[INET_ADDRSTRLEN];
	struct in_addr srcip;
	struct in_addr dstip;
	srcip.s_addr = cb.supss.sip;
	dstip.s_addr = cb.supss.dip;
	inet_ntop(AF_INET, &srcip, ipsrc, INET_ADRSTRLEN);
	inet_ntop(AF_INET, &dstip, ipdst, INET_ADRSTRLEN);
	sprintf(buf, "src host %s and dst host %s and src port %u and dst port %u",
		ipsrc, ipdst, cb.supss.sport, cb.supss.dport);

	std::string exp(buf, strlen(buf));
	bpf->add_filter(0, exp, cb.sc, cb.sc_len);
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
