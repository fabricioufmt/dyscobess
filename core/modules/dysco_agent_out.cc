#include "dysco_agent_out.h"
#include "../module_graph.h"

char* printip2(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
}

CommandResponse DyscoAgentOut::Init(const bess::pb::DyscoAgentOutArg& arg) {
	if(!arg.dc().length())
		return CommandFailure(EINVAL, "'dc' must be given as string.");

	const auto& it = ModuleGraph::GetAllModules().find(arg.dc().c_str());
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found.", arg.dc().c_str());

	dc = reinterpret_cast<DyscoCenter*>(it->second);
	if(!dc)
		return CommandFailure(ENODEV, "DyscoCenter module is NULL.");

	return CommandSuccess();
}

bool DyscoAgentOut::process_packet(bess::Packet* pkt) {
	if(!dc)
		return false;
			
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	uint32_t pkt_index = ((uint32_t*)pkt->metadata<const char*>())[0];
	
	fprintf(stderr, "%s(IN)[%u]: %s:%u -> %s:%u\n", name().c_str(), pkt_index,
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());
	
	DyscoTcpSession* ss = dc->get_supss_by_subss(pkt_index, ip, tcp);
	if(!ss) {
		fprintf(stderr, "%s: get_supss_by_subss is NULL\n", name().c_str());
		return false;
	}
	
	fprintf(stderr, "%s: get_supss_by_subss is not NULL\n", name().c_str());
	
	ip->src = be32_t(ntohl(ss->sip));
	ip->dst = be32_t(ntohl(ss->dip));
	tcp->src_port = be16_t(ntohs(ss->sport));
	tcp->dst_port = be16_t(ntohs(ss->dport));

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	
	fprintf(stderr, "%s(OUT)[%u]: %s:%u -> %s:%u\n", name().c_str(), pkt_index,
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());
	
	return true;
}

void DyscoAgentOut::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming")
