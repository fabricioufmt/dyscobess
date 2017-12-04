#include "dysco_agent_out.h"
#include "../module_graph.h"

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	index = 0;
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

	index = dc->get_index(this->name());
	
	return CommandSuccess();
}

bool DyscoAgentOut::process_packet(bess::Packet* pkt) {
	const uint8_t* metadata = pkt->metadata<uint8_t*>();
	fprintf(stderr, "DyscoAgentOut(metadata): %c\n", metadata[0]);
	
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
