#include "dysco_center.h"

DyscoCenter::DyscoCenter() : Module() {

}

DyscoTcpSession* DyscoCenter::get_session(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.value();
	ss.dip = ip->dst.value();
	ss.sport = tcp->src_port.value();
	ss.dport = tcp->dst_port.value();

	printf("size: %lu\n", map.Count());

	bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>::iterator itt = map.begin();
	while(itt != map.end()) {
		printf("itrator\n");
		itt++;
	}
	auto* it = map.Find(ss);
	if(it != nullptr) {
		return &it->second.supss;
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
	printf("size b4 insert: %lu\n", map.Count());
	map.Insert(ss, cb);
	printf("size after insert: %lu\n", map.Count());
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
