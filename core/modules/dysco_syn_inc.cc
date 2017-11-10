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
/*
  When DyscoSynInc receives SYN segment, it forwards this segment.
 */
void DyscoSynInc::ProcessBatch(bess::PacketBatch* batch) {
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynInc, "dysco_syn_inc", "processes TCP SYN segments incoming")
