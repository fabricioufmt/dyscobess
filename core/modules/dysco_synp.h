#ifndef BESS_MODULES_DYSCOSYNP_H_
#define BESS_MODULES_DYSCOSYNP_H_

#include <rte_config.h>
#include <rte_hash_crc.h>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_policycenter.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

class DyscoSynP final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	//static const gate_idx_t kNumOGates = 2;

 DyscoSynP() : Module() {}
	CommandResponse Init(const bess::pb::DyscoSynPArg& arg);
	void ProcessBatch(bess::PacketBatch*) override;
  
 private:
	DyscoPolicyCenter* dyscopolicy;
	void process_packet(bess::Packet*);
	void remove_payload(bess::Packet*);
};

#endif
