#ifndef BESS_MODULES_ARP_QUERIER_H_
#define BESS_MODULES_ARP_QUERIER_H_

#include <map>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/arp.h"
#include "../utils/ip.h"

using bess::utils::Arp;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;

class Arp_Entry {
 public:
	Ethernet::Address mac;
	std::vector<bess::Packet*> pkts;
	bool sent_request;

	Arp_Entry() {
		sent_request = false;
	}
};

class ArpQuerier final : public Module {
 public:
	static const gate_idx_t kNumIGates = 2;
	static const gate_idx_t kNumOGates = 1;

	void ProcessBatch(bess::PacketBatch* batch) override;

 private:
	std::map<be32_t, Arp_Entry> entries_;

	void ProcessBatchIP(bess::PacketBatch*);
	void ProcessBatchArp(bess::PacketBatch*);
	void updateArpEntry(Ethernet*, Arp*, bess::PacketBatch*);
	void updateSrcEthEntry(Ethernet*, Ipv4*);
	bess::Packet* updateDst(bess::Packet*, Ethernet*, Ipv4*);
	bess::Packet* createArpRequest(Ethernet*, Ipv4*);
};

#endif  // BESS_MODULES_ARP_QUERIER_H_
