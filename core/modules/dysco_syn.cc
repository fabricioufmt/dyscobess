#include "dysco_syn.h"
#include "../module_graph.h"

CommandResponse DyscoSyn::Init(const bess::pb::DyscoSyn& arg) {
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

void DyscoSyn::ProcessBatch(bess::PacketBatch* batch) {
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSyn, "dysco_syn", "processes TCP SYN segment")
