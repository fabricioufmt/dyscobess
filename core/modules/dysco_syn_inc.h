#ifndef BESS_MODULES_DYSCOSYNINC_H_
#define BESS_MODULES_DYSCOSYNINC_H_

#include <stdio.h>
#include <arpa/inet.h>

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

class DyscoSynInc final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

 DyscoSynInc() : Module() {
		dyscocenter = 0;
	}
	CommandResponse Init(const bess::pb::DyscoSynIncArg&);
	void ProcessBatch(bess::PacketBatch*) override;
	void debug_info(bess::Packet*, char*);
	bool process_packet(bess::Packet*);

 private:
	DyscoCenter* dyscocenter;
};

#endif //BESS_MODULES_DYSCOSYNINC_H_
