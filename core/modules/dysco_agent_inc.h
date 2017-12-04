#ifndef BESS_MODULES_DYSCOAGENTINC_H_
#define BESS_MODULES_DYSCOAGENTINC_H_

#include <stdio.h>
#include <arpa/inet.h>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_center.h"
#include "dysco_utils.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

class DyscoAgentInc final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

	DyscoAgentInc();
	bool process_nonsyn(Ipv4*, Tcp*);
	bool process_packet(bess::Packet*);
	bool insert_metadata(bess::Packet*);
	bool process_syn(bess::Packet*, Ipv4*, Tcp*);
	bool process_synp(bess::Packet*, Ipv4*, Tcp*);
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentIncArg&);

 private:
	uint32_t index;
	DyscoCenter* dc;
};

#endif //BESS_MODULES_DYSCOAGENTINC_H_
