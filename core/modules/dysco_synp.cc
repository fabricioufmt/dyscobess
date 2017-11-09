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

void DyscoSynP::remove_payload(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	uint32_t trim_len = ip->length.value() - tcp->offset * 4 - ip_hlen;

	if(trim_len)
		pkt->trim(trim_len);

	ip->length = ip->length - be16_t(trim_len);
}

void DyscoSynP::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_len = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);
	//DyscoTcpSession* supss = (DyscoTcpSession*) payload;
	
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
