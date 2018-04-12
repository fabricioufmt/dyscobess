#ifndef BESS_MODULES_FIXMAC_H_
#define BESS_MODULES_FIXMAC_H_

#include <map>

#include "../module.h"
#include "../utils/ether.h"
#include "../pb/module_msg.pb.h"

using bess::utils::Ethernet;

struct mac_entry {
	Ethernet::Address addr;
	gate_idx_t gate;
};

class FixMac final : public Module {
 public:
	static const gate_idx_t kNumOGates = MAX_GATES;
	static const Commands cmds;

 FixMac() : Module(), _entries() {
		
	}

	~FixMac() {
		_entries.clear();
	}
	
	CommandResponse Init(const bess::pb::FixMac&);
	void ProcessBatch(bess::PacketBatch*) override;
	bool forward(bess::Packet*, gate_idx_t*);
	bool forward_mac(Ethernet::Address, gate_idx_t*);

	CommandResponse CommandAdd(const bess::pb::FixMacCommandAddArg&);

 private:
	uint32_t ngates;
	std::map<be32_t, struct mac_entry> _entries;
};

#endif
