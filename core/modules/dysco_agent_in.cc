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
	
	inet_pton(AF_INET, arg.ip().c_str(), &devip);
	index = dc->get_index(arg.ns(), devip);
	ns = arg.ns();
	
	return CommandSuccess();
}
/**
   TODO: Do nothing?
 */
bool DyscoAgentIn::process_syn(bess::Packet*, Ipv4*, Tcp*) {
	return true;
}

bool DyscoAgentIn::process_synp(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);

	DyscoHashIn* cb_in = dc->insert_cb_in(this->index, ip, tcp, payload, payload_sz);
	if(!cb_in) {
		fprintf(stderr, "[%s]%s: cb_in(insert) is NULL\n", ns.c_str(), name().c_str());
		return false;
	}
	fprintf(stderr, "[%s]%s: cb_in(insert) is not NULL\n", ns.c_str(), name().c_str());
	
	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	//TODO: parse TCP Options
	//TODO: Dysco Tag
	
	ip->src = be32_t(ntohl(supss->sip));
	ip->dst = be32_t(ntohl(supss->dip));
	tcp->src_port = be16_t(ntohs(supss->sport));
	tcp->dst_port = be16_t(ntohs(supss->dport));

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	return true;
}

bool DyscoAgentIn::process_nonsyn(bess::Packet*, Ipv4*, Tcp*) {
	return true;
}

bool DyscoAgentIn::process_packet(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	
	fprintf(stderr, "[%s]%s(IN): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());

	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);

	if(!cb_in) {
		fprintf(stderr, "[%s]%s: cb_in(lookup) is NULL\n", ns.c_str(), name().c_str());
		if(isTCPSYN(tcp) && hasPayload(ip, tcp))
			return process_synp(pkt, ip, tcp);
		
		return false;
	}
	DyscoTcpSession* sub = cb_in->get_sub();
	DyscoTcpSession* sup = cb_in->get_sup();
	fprintf(stderr, "[%s]%s: cb_in(lookup) is not NULL\n", ns.c_str(), name().c_str());
	fprintf(stderr, "[%s] cb_in:\n", ns.c_str());
	fprintf(stderr, "[%s]: (SUB)%s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ntohl(sub->sip)), ntohs(sub->sport),
		printip1(ntohl(sub->dip)), ntohs(sub->dport));
	fprintf(stderr, "[%s]: (SUP)%s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ntohl(sup->sip)), ntohs(sup->sport),
		printip1(ntohl(sup->dip)), ntohs(sup->dport));
	//TODO: remaing
	
	DyscoTcpSession* sup = cb_in->get_sup();
	ip->src = be32_t(ntohl(sup->sip));
	ip->dst = be32_t(ntohl(sup->dip));
	tcp->src_port = be16_t(ntohs(sup->sport));
	tcp->dst_port = be16_t(ntohs(sup->dport));

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	
	fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	return true;
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
	if(dc) {
		int cnt = batch->cnt();
		
		bess::Packet* pkt = 0;
		for(int i = 0; i < cnt; i++) {
			pkt = batch->pkts()[i];
			process_packet(pkt);
		}
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
