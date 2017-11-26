#include "dysco_syn_out.h"
#include "../module_graph.h"

CommandResponse DyscoSynOut::Init(const bess::pb::DyscoSynOutArg& arg) {
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
/*
  Receives ControlBlock searching for supss like as packet.
  We assume that this packet come from a VPort without modification
  and
  We assume that DyscoCenter already matched with highest-priority rule on policies.
 */
bool DyscoSynOut::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	if(!dyscocenter)
		return false;

	//These must be merge into a single DyscoControlBlock
	DyscoBPF::Filter* filter = dyscocenter->get_filter(pkt);
	DyscoControlBlock* cb = dyscocenter->get_controlblock_supss(ip, tcp);

	if(!cb)
		fprintf(stderr, "DyscoSynOut: cb is NULL\n");
	if(!filter)
		fprintf(stderr, "DyscoSynOut: filter is NULL\n");		
	
	if(!cb || !filter)
		return false;
	
	DyscoTcpSession* ss = &cb->nextss;
	ip->src = be32_t(ss->sip);
	ip->dst = be32_t(ss->dip);
	tcp->src_port = be16_t(ss->sport);
	tcp->dst_port = be16_t(ss->dport);

	uint32_t payload_len = sizeof(DyscoTcpSession) + filter->sc_len;
	uint8_t* payload = (uint8_t*) pkt->append(payload_len);
	memcpy(payload, &cb->supss, sizeof(DyscoTcpSession));
	memcpy(payload + sizeof(DyscoTcpSession), filter->sc, filter->sc_len);

	ip->length = be16_t(ip->length.value() + payload_len);

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	
	return true;
}

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

void DyscoSynOut::debug_info(bess::Packet* pkt, char* dir) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	fprintf(stderr, "DyscoSynOut(%s): %s:%u -> %s:%u\n", dir
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
}

/*
  When DyscoSynOut receives SYN segment, it checks any policy rule on DyscoCenter. 
 */
void DyscoSynOut::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();
	
	bess::Packet* pkt;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		debug_info(pkt, "in");
		process_packet(pkt);
		debug_info(pkt, "out");
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynOut, "dysco_syn_out", "processes TCP SYN segments outcoming")
