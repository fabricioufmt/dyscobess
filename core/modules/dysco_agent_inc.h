#ifndef BESS_MODULES_DYSCOAGENTINC_H_
#define BESS_MODULES_DYSCOAGENTINC_H_

#include <stdio.h>
#include <arpa/inet.h>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_center.h"

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

	inline bool isIP(Ethernet* eth) {
		return eth->ether_type.value() == Ethernet::Type::kIpv4;
	}

	inline bool isTCP(Ipv4* ip) {
		return ip->protocol == Ipv4::Proto::kTcp;
	}

	inline bool isTCPSYN(Tcp* tcp) {
		return tcp->flags == Tcp::Flag::kSyn;
	}

	inline bool hasPayload(Ipv4* ip, Tcp* tcp) {
		size_t ip_hlen = ip->header_length << 2;
		size_t tcp_hlen = tcp->offset << 2;

		return ip->length.value() - ip_hlen - tcp_hlen;
	}

 private:
	uint32_t index;
	DyscoCenter* dc;
};

#endif //BESS_MODULES_DYSCOAGENTINC_H_
