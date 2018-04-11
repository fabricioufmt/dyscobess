#ifndef BESS_MODULES_ETHERSWITCH_H_
#define BESS_MODULES_ETHERSWITCH_H_

#include <unordered_map>

#include "../module.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../pb/module_msg.pb.h"

using bess::utils::Ethernet;

class EtherSwitch final : public Module {
 private:
	std::unordered_map<Ethernet::Address, gate_idx_t> _entries;
	
 public:
 EtherSwitch() : Module(), _entries() {
	}
	
	static const gate_idx_t kNumOGates = MAX_GATES;
	static const Commands cmds;

	CommandResponse Init(const bess::pb::EtherSwitchArg&);
	void DeInit() override;
	void ProcessBatch(bess::PacketBatch*) override;
	bool isBroadcast(bess::Packet*, gate_idx_t, gate_idx_t*);

	CommandResponse CommandAdd(const bess::pb::EtherSwitchCommandAddArg&);
	CommandResponse CommandDel(const bess::pb::EtherSwitchCommandDelArg&);
};

#endif
