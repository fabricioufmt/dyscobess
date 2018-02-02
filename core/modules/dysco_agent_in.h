#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

#include <stdio.h>
#include <arpa/inet.h>

#include "../port.h"
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

class DyscoAgentIn final : public Module {
 public:
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

	DyscoAgentIn();
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);

 private:
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	std::string ns;

	inline bool isIP(Ethernet* eth) {
		return eth->ether_type.value() == Ethernet::Type::kIpv4;
	}

	inline bool isTCP(Ipv4* ip) {
		return ip->protocol == Ipv4::Proto::kTcp;
	}

	inline bool isTCPSYN(Tcp* tcp) {
		return tcp->flags == Tcp::Flag::kSyn;
	}

	inline bool isTCPACK(Tcp* tcp) {
		return tcp->flags == Tcp::Flag::kAck;
	}

	inline bool hasPayload(Ipv4* ip, Tcp* tcp) {
		size_t ip_hlen = ip->header_length << 2;
		size_t tcp_hlen = tcp->offset << 2;

		return ip->length.value() - ip_hlen - tcp_hlen;
	}

	/*
	  Dysco methods
	 */
 
	bool remove_sc(bess::Packet*, Ipv4*, Tcp*);
	bool in_hdr_rewrite(Ipv4*, Tcp*, DyscoTcpSession*);
	bool in_rewrite_seq(Tcp*, DyscoHashIn*);
	bool in_rewrite_ack(Tcp*, DyscoHashIn*);
	bool in_rewrite_ts(Tcp*, DyscoHashIn*);
	bool in_rewrite_rcv_wnd(Tcp*, DyscoHashIn*);
	bool in_hdr_rewrite_csum(Ipv4*, Tcp*, DyscoHashIn*);
	bool rx_initiation_new(bess::Packet*, Ipv4*, Tcp*);
	bool set_ack_number_out(uint32_t, Tcp*, DyscoHashIn*);
	//bool set_zero_window(Tcp*);
	bool in_two_paths_ack(Tcp*, DyscoHashIn*);
	bool in_two_paths_data_seg(Tcp*, DyscoHashIn*);
	bool input(bess::Packet*);


	/*
	  Control methods
	 */
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, DyscoControlMessage*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);
	bool control_reconfig_in(Ipv4*, DyscoCbReconfig*, DyscoControlMessage*);
	bool control_input(Ipv4*);



	

	bool tcp_sack(Tcp*, DyscoHashIn*);
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
