#include "dysco_nonsyn_out.h"
#include "../module_graph.h"

CommandResponse DyscoNonSynOut::Init(const bess::pb::DyscoNonSynOutArg& arg) {
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

bool DyscoNonSynOut::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	if(!dyscocenter)
		return false;
	
	DyscoTcpSession* supss = dyscocenter->get_session(ip, tcp);

	if(!supss)
		return false;
	
	ip->src = be32_t(supss->sip);
	ip->dst = be32_t(supss->dip);
	tcp->src_port = be16_t(supss->sport);
	tcp->dst_port = be16_t(supss->dport);

	return true;
}

void DyscoNonSynOut::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoNonSynOut, "dysco_nonsyn_out", "processes TCP NON-SYN segments outcoming")
