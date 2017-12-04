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

bool DyscoAgentInc::process_packet(bess::Packet* pkt) {
	*(pkt->metadata<char*>()) = 'b';
	
	return true;
}

void DyscoAgentInc::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		process_packet(pkt);
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentInc, "dysco_agent_inc", "processes packets incoming")
