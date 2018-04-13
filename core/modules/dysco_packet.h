#ifndef BESS_MODULES_DYSCO_PACKET_H_
#define BESS_MODULES_DYSCO_PACKET_H_

#include "../module.h"
#include "../utils/ether.h"

#define dysco_mac "00:00:00:00:00:00"

using bess::utils::Ethernet;

class DyscoPacket final : public Module {
 public:
 DyscoPacket() : Module() {}

	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;
	
	CommandResponse Init(const bess::pb::EmptyArg&);
	void ProcessBatch(bess::PacketBatch*);
};

#endif
