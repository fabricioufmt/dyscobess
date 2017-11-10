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

void DyscoSynOut::ProcessBatch(bess::PacketBatch* batch) {
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynOut, "dysco_syn_out", "processes TCP SYN segments outcoming")
