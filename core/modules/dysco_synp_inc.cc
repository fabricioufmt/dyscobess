#include <arpa/inet.h>
#include "dysco_synp_inc.h"
#include "../module_graph.h"

CommandResponse DyscoSynPInc::Init(const bess::pb::DyscoSynPIncArg& arg) {
	const char* module_name;
	if(!arg.dyscocenter().length())
		return CommandFailure(EINVAL, "'dyscopolicy' must be given as string");

	module_name = arg.dyscocenter().c_str();

	const auto &it = ModuleGraph::GetAllModules().find(module_name);
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found", module_name);

	dyscocenter = reinterpret_cast<DyscoCenter*>(it->second);
	
	return CommandSuccess();
}

void DyscoSynPInc::remove_payload(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	uint32_t trim_len = ip->length.value() - tcp->offset * 4 - ip_hlen;

	if(trim_len) {
		pkt->trim(trim_len);
		ip->length = ip->length - be16_t(trim_len);
	}

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
}

bool DyscoSynPInc::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_len = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);

	if(!dyscocenter)
		return false;
	
	dyscocenter->add_mapping(ip, tcp, payload, payload_len);
	
	ip->src = be32_t(ntohl(supss->sip));
	ip->dst = be32_t(ntohl(supss->dip));
	tcp->src_port = be16_t(ntohs(supss->sport));
	tcp->dst_port = be16_t(ntohs(supss->dport));

	return true;
}

void DyscoSynPInc::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
		remove_payload(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynPInc, "dysco_synp_inc", "processes TCP SYN with Payload segments incoming")
