#ifndef BESS_MODULES_L2FWD_H_
#define BESS_MODULES_L2FWD_H_

#include <map>
#include <unordered_map>

#include "../module.h"
#include "../utils/ether.h"

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

class L2FWD final : public Module {
 private:
	std::unordered_map<Ethernet::Address, gate_idx_t, HashEtherAddr> _entries;

 public:
 L2FWD(): Module(), _entries() {
	}

	~L2FWD() {
		DeInit();
	}
	
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = MAX_GATES;

	CommandResponse Init(const bess::pb::L2FWDArg&);
	void DeInit() override;
	bool isKnown(Ethernet::Address);
	bool isBroadcast(Ethernet::Address);
	void ProcessBatch(bess::PacketBatch*);
	
	CommandResponse CommandAdd(const bess::pb::L2FWDCommandAddArg&);
};

#endif
