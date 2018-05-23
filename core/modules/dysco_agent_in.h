#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

#include <chrono>
#include <thread>
#include <vector>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "dysco_center.h"

#include "../port.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/dysco_vport.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

//in ms
#define SLEEPTIME 1

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

enum CONTROL_RETURN {
	TO_GATE_0,
	TO_GATE_1,
	IS_RETRANSMISSION,
	MIDDLE,
	ERROR,
	END
};

class DyscoAgentIn final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;

	DyscoAgentIn();
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	CommandResponse CommandInfo(const bess::pb::EmptyArg&);
	
 private:
	uint32_t devip;
	uint32_t index;
	std::string ns;
	DyscoCenter* dc;
	uint32_t timeout;
	DyscoVPort* port;
	static std::vector<DyscoAgentIn*> instances;

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

	inline bool isToLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->dst.value() == ntohl(cmsg->leftA);
	}


	inline bool isToRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->dst.value() == ntohl(cmsg->rightA);
	}
	
	/*
	  Dysco methods
	 */
	bool tcp_sack(Tcp*, DyscoHashIn*); 
	bool remove_sc(bess::Packet*, Ipv4*, Tcp*);
	bool in_hdr_rewrite(Ipv4*, Tcp*, DyscoTcpSession*);
	bool in_rewrite_seq(Tcp*, DyscoHashIn*);
	bool in_rewrite_ack(Tcp*, DyscoHashIn*);
	bool in_rewrite_ts(Tcp*, DyscoHashIn*);
	bool in_rewrite_rcv_wnd(Tcp*, DyscoHashIn*);
	bool in_hdr_rewrite_csum(Ipv4*, Tcp*, DyscoHashIn*);
	bool rx_initiation_new(bess::Packet*, Ipv4*, Tcp*);
	bool in_two_paths_ack(Tcp*, DyscoHashIn*);
	bool in_two_paths_data_seg(Tcp*, DyscoHashIn*);
	CONTROL_RETURN input(bess::Packet*, Ipv4*, Tcp*, DyscoHashIn*);

	/*
	  Dysco control methods
	 */
	bool isReconfigPacket(Ipv4*, Tcp*, DyscoHashIn*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, Tcp*, DyscoControlMessage*);
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);
	CONTROL_RETURN control_reconfig_in(bess::Packet*, Ipv4*, Tcp*, uint8_t*, DyscoCbReconfig*, DyscoControlMessage*);
	CONTROL_RETURN control_input(bess::Packet*, Ipv4*, Tcp*, DyscoHashIn*);

	/*
	  Auxiliary methods
	 */
	bool setup();
	void createAck(bess::Packet*, Ipv4*, Tcp*);
	void createSynAck(bess::Packet*, Ipv4*, Tcp*);
	void createFinAck(bess::Packet*, Ipv4*, Tcp*);

	/*
	  TCP Retransmission methods
	 */
	void retransmissionHandler();
	bool addToRetransmission(bess::Packet*);
	bool processReceivedPackets(Ipv4*, Tcp*);

	static void callHandlers(int) {
		std::for_each(instances.begin(), instances.end(), std::mem_fun(&DyscoAgentIn::retransmissionHandler));
	}
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
