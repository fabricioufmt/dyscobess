#ifndef BESS_MODULES_FIXMAC_H_
#define BESS_MODULES_FIXMAC_H_

#include <map>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../pb/module_msg.pb.h"

using bess::utils::Ipv4;
using bess::utils::be32_t;
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

	inline bool isIP(Ethernet* eth) {
		return eth->ether_type.value() == Ethernet::Type::kIpv4;
	}
	
	CommandResponse Init(const bess::pb::FixMacArg&);
	void ProcessBatch(bess::PacketBatch*) override;
	bool forward(bess::Packet*, gate_idx_t*);
	bool forward_mac(Ethernet::Address, gate_idx_t*);

	CommandResponse CommandAdd(const bess::pb::FixMacCommandAddArg&);

 private:
	uint32_t ngates;
	std::map<be32_t, struct mac_entry> _entries;
};

#endif
