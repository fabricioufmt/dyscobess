#include "dysco_syn_inc.h"
#include "../module_graph.h"

CommandResponse DyscoSynInc::Init(const bess::pb::DyscoSynIncArg& arg) {
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

char* printip(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

void DyscoSynInc::debug_info(bess::Packet* pkt, char* dir) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	fprintf(stderr, "DyscoSynInc(%s): %s:%u -> %s:%u\n", dir,
		printip(ip->src.value()), tcp->src_port.value(),
		printip(ip->dst.value()), tcp->dst_port.value());
}

/*
  When DyscoSynInc receives SYN segment, it forwards this segment.
 */
void DyscoSynInc::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		debug_info(pkt, (char*)"in/out");
	}
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynInc, "dysco_syn_inc", "processes TCP SYN segments incoming")
