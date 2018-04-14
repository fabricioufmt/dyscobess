#ifndef BESS_MODULES_UPDATEMAC_H_
#define BESS_MODULES_UPDATEMAC_H_

#include "../module.h"
#include "../utils/ether.h"
#include "../pb/module_msg.pb.h"

#define DEFAULT_MAC "00:00:00:00:00:00"

using bess::utils::Ethernet;

class UpdateMac final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

 UpdateMac() : Module() {
		mac_addr.FromString(DEFAULT_MAC);
	}

	CommandResponse Init(const bess::pb::UpdateMacArg&);
	void ProcessBatch(bess::PacketBatch*);

 private:
	Ethernet::Address mac_addr;
};

#endif
