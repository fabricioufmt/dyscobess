#include "dysco_agent_inc.h"
#include "../module_graph.h"

DyscoAgentInc::DyscoAgentInc() : Module() {
	dc = 0;
	index = 0;
}

CommandResponse DyscoAgentInc::Init(const bess::pb::DyscoAgentIncArg& arg) {
	if(!arg.dc().length())
		return CommandFailure(EINVAL, "'dc' must be given as string.");

	const auto& it = ModuleGraph::GetAllModules().find(arg.dc().c_str());
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found.", arg.dc().c_str());

	dc = reinterpret_cast<DyscoCenter*>(it->second);
	if(!dc)
		return CommandFailure(ENODEV, "DyscoCenter module is NULL.");

	index = dc->get_index(this->name());
	
	return CommandSuccess();
}

bool DyscoAgentInc::process_syn(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	if(!dc)
		return false;

	DyscoControlBlock* cb = dc->get_controlblock_by_supss(this->index, ip, tcp);
	if(!cb) {
		fprintf(stderr, "DyscoAgentInc(syn): cb is NULL\n");

		DyscoBPF::Filter* f = dc->get_filter(pkt);
		if(!f) {
			fprintf(stderr, "DyscoAgentInc(syn): filter is NULL\n");
			return false;
		}

		fprintf(stderr, "DyscoAgentInc(syn): filter is not NULL\n");
		cb = dc->add_mapping_filter(this->index, ip, tcp, f);
		if(!cb)
			return false;
		
	}
	fprintf(stderr, "DyscoAgentInc(syn): cb is not NULL\n");
	
	DyscoTcpSession* ss = &cb->subss;
	ip->src = be32_t(ntohl(ss->sip));
	ip->dst = be32_t(ntohl(ss->dip));
	tcp->src_port = be16_t(ntohs(ss->sport));
	tcp->dst_port = be16_t(ntohs(ss->dport));
			
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
}

bool DyscoAgentInc::process_synp(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	if(!dc)
		return false;
	
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_len = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoTcpSession* supss = reinterpret_cast<DyscoTcpSession*>(payload);

	dc->add_mapping(this->index, ip, tcp, payload, payload_len);
	
	ip->src = be32_t(ntohl(supss->sip));
	ip->dst = be32_t(ntohl(supss->dip));
	tcp->src_port = be16_t(ntohs(supss->sport));
	tcp->dst_port = be16_t(ntohs(supss->dport));

	pkt->trim(payload_len);
	ip->length = ip->length - be16_t(payload_len);

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
}

bool DyscoAgentInc::process_nonsyn(Ipv4* ip, Tcp* tcp) {
	if(!dc)
		return false;

	DyscoTcpSession* ss = dc->get_subss_by_supss(this->index, ip, tcp);
	if(!ss)
		return false;
	
	ip->src = be32_t(ss->sip);
	ip->dst = be32_t(ss->dip);
	tcp->src_port = be16_t(ss->sport);
	tcp->dst_port = be16_t(ss->dport);

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	
	return true;
}

bool DyscoAgentInc::insert_metadata(bess::Packet* pkt) {
	uint32_t* metadata = (uint32_t*) _ptr_attr_with_offset<uint8_t>(0, pkt);
	metadata[0] = index;
	
	return true;
}

bool DyscoAgentInc::process_packet(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	if(isTCPSYN(tcp)) {
		if(hasPayload(ip, tcp))
			process_synp(pkt, ip, tcp);
		else
			process_syn(pkt, ip, tcp);
	} else
		process_nonsyn(ip, tcp);
	
	return true;
}

void DyscoAgentInc::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
		insert_metadata(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentInc, "dysco_agent_inc", "processes packets incoming")
