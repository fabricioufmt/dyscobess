#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include <stdio.h>
#include <arpa/inet.h>

#include "dysco_center.h"

#include "../port.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/dysco_vport.h"

#include "../utils/ip.h"
#include "../utils/arp.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

#define DYSCO_MAC "00:00:00:00:00:00"

#define DEBUG 1

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

class DyscoAgentOut final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

	DyscoAgentOut();

	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentOutArg&);
	CommandResponse CommandInfo(const bess::pb::EmptyArg&);
	
 private:
	uint32_t devip;
	uint32_t index;
	std::string ns;
	DyscoCenter* dc;
	DyscoVPort* port;
	
	inline bool isIP(Ethernet* eth) {
		return eth->ether_type.value() == Ethernet::Type::kIpv4;
	}

	inline bool isTCP(Ipv4* ip) {
		return ip->protocol == Ipv4::Proto::kTcp;
	}

	inline bool isTCPSYN(Tcp* tcp, bool exclusive = false) {
		return exclusive ? tcp->flags == Tcp::Flag::kSyn : tcp->flags & Tcp::Flag::kSyn;
	}

	inline bool isTCPACK(Tcp* tcp, bool exclusive = false) {
		return exclusive ? tcp->flags == Tcp::Flag::kAck : tcp->flags & Tcp::Flag::kAck;
	}

	inline uint32_t hasPayload(Ipv4* ip, Tcp* tcp) {
		return ip->length.value() - (ip->header_length << 2) - (tcp->offset << 2);
	}

	inline bool isFromLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->src.value() == ntohl(cmsg->leftA);
	}


	inline bool isFromRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->src.value() == ntohl(cmsg->rightA);
	}

	inline bool isToLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->dst.value() == ntohl(cmsg->leftA);
	}


	inline bool isToRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->dst.value() == ntohl(cmsg->rightA);
	}

	/*
	  Dysco methods
	 */
	bool isReconfigPacket(Ipv4*, Tcp*, DyscoHashOut*);
	bool out_rewrite_seq(Tcp*, DyscoHashOut*);
	bool out_rewrite_ack(Tcp*, DyscoHashOut*);
	bool out_rewrite_ts(Tcp*, DyscoHashOut*);
	bool out_rewrite_rcv_wnd(Tcp*, DyscoHashOut*);
	DyscoHashOut* pick_path_seq(DyscoHashOut*, uint32_t);
	DyscoHashOut* pick_path_ack(Tcp*, DyscoHashOut*);
	bool out_translate(bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool update_five_tuple(Ipv4*, Tcp*, DyscoHashOut*);
	bool output(bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	
	/*
	  Dysco control methods
	 */
	DyscoCbReconfig* insert_cb_control(Ipv4*, Tcp*, DyscoControlMessage*);
	bool control_insert_out(DyscoCbReconfig*);
	bool replace_cb_rightA(DyscoControlMessage*);
	bool replace_cb_leftA(DyscoCbReconfig*, DyscoControlMessage*);
	bool control_output_syn(Ipv4*, Tcp*, DyscoControlMessage*);
	bool control_output(Ipv4*, Tcp*);

	/*
	  Auxiliary methods
	 */
	bool get_port_information();
	void dysco_packet(Ethernet*);
};

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
