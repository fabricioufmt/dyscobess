#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include <stdio.h>
#include <arpa/inet.h>

#include "../port.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_center.h"
#include "../drivers/dysco_vport.h"

#include "../utils/ip.h"
#include "../utils/arp.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

#define DYSCO_MAC "00:00:00:00:00:00"

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
	
	//Dysco
	bool get_port_information();

	/*

	 */
	void dysco_packet(Ethernet*);
	void process_arp(bess::Packet*);
	void process_ethernet(bess::Packet*);
	
 private:
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	std::string ns;
	int netns_fd_;
	bool info_flag;
	DyscoVPort* port;
	
	bool insert_metadata(bess::Packet*);
	
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
		size_t ip_hlen = ip->header_length << 2;
		size_t tcp_hlen = tcp->offset << 2;

		return ip->length.value() - ip_hlen - tcp_hlen;
	}

	inline bool isLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->src.value() == ntohl(cmsg->leftA);
	}


	inline bool isRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->src.value() == ntohl(cmsg->rightA);
	}
	
	inline bool isReconfigPacket(Ipv4* ip, Tcp* tcp) {
		if(isTCPSYN(tcp, true)) {
			uint32_t payload_len = hasPayload(ip, tcp);
			if(payload_len) {
				//Only LeftAnchor
				uint32_t tcp_hlen = tcp->offset << 2;
				if(((uint8_t*)tcp + tcp_hlen)[payload_len - 1] == 0xFF)
					return true;
				
				return false;
			}

			//Hosts in the middle (left - middle - right)
			DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
			if(!cb_out)
				return false;

			if(!cb_out->dcb_in) {
				fprintf(stderr, "[DyscoCenter]: cb_out->dcb_in is NULL\n");
				return false;
			}
			
			if(cb_out->dcb_in->is_reconfiguration)
				return true;

			return false;
		}

		return false;
	}

	bool out_rewrite_seq(Tcp*, DyscoHashOut*);
	bool out_rewrite_ack(Tcp*, DyscoHashOut*);
	bool out_rewrite_ts(Tcp*, DyscoHashOut*);
	bool out_rewrite_rcv_wnd(Tcp*, DyscoHashOut*);
	DyscoHashOut* pick_path_seq(DyscoHashOut*, uint32_t);
	DyscoHashOut* pick_path_ack(Tcp*, DyscoHashOut*);
	bool out_translate(bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool update_five_tuple(Ipv4*, Tcp*, DyscoHashOut*);
	bool output(bess::Packet*, Ipv4*, Tcp*);
	/*
	  CONTROL
	 */

	DyscoCbReconfig* insert_cb_control(Ipv4*, Tcp*, DyscoControlMessage*);
	bool control_insert_out(DyscoCbReconfig*);
	bool replace_cb_rightA(DyscoControlMessage*);
	bool replace_cb_leftA(DyscoCbReconfig*, DyscoControlMessage*);
	bool control_output_syn(Ipv4*, Tcp*, DyscoControlMessage*);
	bool control_output(Ipv4*, Tcp*);
};

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
