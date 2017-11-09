#include "dysco_synp.h"
#include "../module_graph.h"

CommandResponse DyscoSynP::Init(const bess::pb::DyscoSynPArg& arg) {
	const char* module_name;
	if(!arg.dyscopolicy().length())
		return CommandFailure(EINVAL, "'dyscopolicy' must be given as string");

	module_name = arg.dyscopolicy().c_str();

	const auto &it = ModuleGraph::GetAllModules().find(module_name);
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found", module_name);

	dyscopolicy = reinterpret_cast<DyscoPolicyCenter*>(it->second);

	return CommandSuccess();
}
/*
void process_packet(bess::Packet* pkt) {
  Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
  size_t tcp_hlen = tcp->offset << 2;
  uint16_t ip_len = ip->length.value();
  uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
  int sc_len = (ip_len - ip_hlen - tcp_hlen - sizeof(struct tcp_session))/sizeof(uint32_t);
  uint32_t* sc = (uint32_t*) (payload + sizeof(struct tcp_session));
  
  struct tcp_session subss;
  struct tcp_session nextss;
  struct tcp_session* supss = (struct tcp_session*) payload;
  subss.sip = ip->src.value();
  subss.dip = ip->dst.value();
  subss.sport = tcp->src_port.value();
  subss.dport = tcp->dst_port.value();
  if(sc_len != 1) {
    next.sip = subss.dip;
    next.dip = sc[1]; //sc[0] is yourself
    next.sport = (rand() % 1000) + 10000;
    next.sport = (rand() % 1000) + 30000;
  } else {
    next.sip = next.dip = 0;
    next.sport = next.dport = 0;
  }
  
  //Send (subss, supss, nextss, sc_len, sc) to DyscoPolicyCenter
}
*/

void DyscoSynP::remove_payload(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	uint32_t trim_length = ip->length.value() - tcp->offset * 4 - ip_hlen;

	if(trim_length)
		pkt->trim(trim_length);

	ip->length = ip->length - be16_t(trim_length);
}

void DyscoSynP::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_len  = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);
	
	dyscopolicy->add(ip, tcp, payload, payload_len);
	
	ip->src = be32_t(supss->sip);
	ip->dst = be32_t(supss->dip);
	tcp->src_port = be16_t(supss->sport);
	tcp->dst_port = be16_t(supss->dport);
}

void DyscoSynP::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
		remove_payload(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynP, "dysco_synp", "processes TCP SYN with Payload segment")
