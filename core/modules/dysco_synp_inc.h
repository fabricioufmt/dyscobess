#ifndef BESS_MODULES_DYSCOSYNPINC_H_
#define BESS_MODULES_DYSCOSYNPINC_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_center.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

class DyscoSynPInc final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

 DyscoSynPInc() : Module() {}
	CommandResponse Init(const bess::pb::DyscoSynPArg&);
	void ProcessBatch(bess::PacketBatch*) override;
  
 private:
	DyscoCenter* dyscocenter;
	void process_packet(bess::Packet*);
	void remove_payload(bess::Packet*);
};

#endif //BESS_MODULES_DYSCOSYNPINC_H_
