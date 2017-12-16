#include "dysco_agent_in.h"
#include "../module_graph.h"

char* printip1(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
}

CommandResponse DyscoAgentIn::Init(const bess::pb::DyscoAgentInArg& arg) {
	if(!arg.dc().length())
		return CommandFailure(EINVAL, "'dc' must be given as string.");

	const auto& it = ModuleGraph::GetAllModules().find(arg.dc().c_str());
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found.", arg.dc().c_str());

	dc = reinterpret_cast<DyscoCenter*>(it->second);
	if(!dc)
		return CommandFailure(ENODEV, "DyscoCenter module is NULL.");
	
	index = dc->get_index(arg.ns());
	
	inet_pton(AF_INET, arg.ip().c_str(), &devip);
	
	return CommandSuccess();
}
/**
   TODO: Do nothing?
 */
bool DyscoAgentIn::process_syn(bess::Packet*, Ipv4*, Tcp*) {
	return true;
}

bool DyscoAgentIn::process_synp(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	if(!dc)
		return false;
	
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);

	DyscoHashIn* cb_in = dc->insert_cb_in(this->index, ip, tcp, payload, payload_sz);
	if(!cb_in)
		return false;
	
	ip->src = be32_t(ntohl(supss->sip));
	ip->dst = be32_t(ntohl(supss->dip));
	tcp->src_port = be16_t(ntohs(supss->sport));
	tcp->dst_port = be16_t(ntohs(supss->dport));

	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
}

bool DyscoAgentIn::process_nonsyn(bess::Packet*, Ipv4*, Tcp*) {
	if(!dc)
		return false;
}

bool DyscoAgentIn::process_packet(bess::Packet* pkt) {
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
	
	fprintf(stderr, "%s(IN)[index: %u]: %s:%u -> %s:%u\n",
		name().c_str(), pkt_index,
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	if(isTCPSYN(tcp)) {
		if(hasPayload(ip, tcp))
			process_synp(pkt, ip, tcp);
		else
			process_syn(pkt, ip, tcp);
	} else
		process_nonsyn(pkt, ip, tcp);
	
	fprintf(stderr, "%s(OUT)[index: %u]: %s:%u -> %s:%u\n",
		name().c_str(), pkt_index,
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	return true;
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
