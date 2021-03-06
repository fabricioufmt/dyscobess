#ifndef BESS_MODULES_ETHERSWITCH_H_
#define BESS_MODULES_ETHERSWITCH_H_

#include <map>
#include <unordered_map>

#include "../module.h"
#include "../utils/ether.h"
#include "../utils/endian.h"

using bess::utils::Ethernet;

struct HashEtherAddr {
	std::size_t operator() (const Ethernet::Address& a) const {
		std::size_t res = std::hash<char>()(a.bytes[0]);
		
		for(uint32_t i = 1; i < Ethernet::Address::kSize; i++) {
			res ^= std::hash<char>()(a.bytes[i]);
		}

		return res;
	}
};

class EtherSwitch final : public Module {
 private:
	std::unordered_map<Ethernet::Address, gate_idx_t, HashEtherAddr> _entries;
	
 public:
 EtherSwitch() : Module(), _entries() {
	}

	~EtherSwitch() {
		DeInit();
	}
	
	static const Commands cmds;
	static const gate_idx_t kNumIGates = MAX_GATES;
	static const gate_idx_t kNumOGates = MAX_GATES;

	CommandResponse Init(const bess::pb::EtherSwitchArg&);
	void DeInit() override;
	void ProcessBatch(bess::PacketBatch*) override;
	bool isBroadcast(bess::Packet*, gate_idx_t, gate_idx_t*);

	CommandResponse CommandAdd(const bess::pb::EtherSwitchCommandAddArg&);
	CommandResponse CommandDel(const bess::pb::EtherSwitchCommandDelArg&);
};

#endif
