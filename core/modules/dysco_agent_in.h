#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

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

#define DEBUG 1
#define DEBUG_RECONFIG 1

#define RECONFIG_SPORT 8988
#define RECONFIG_DPORT 8989

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

char* printiptest1(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

class DyscoAgentIn final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;

	DyscoAgentIn();
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	CommandResponse CommandInfo(const bess::pb::EmptyArg&);

	//Dysco
	bool get_port_information();

 private:
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	//char ns[256];
	std::string ns;
	int netns_fd_;
	bool info_flag;
	DyscoVPort* port;

	inline bool isARP(Ethernet* eth) {
		return eth->ether_type.value() == Ethernet::Type::kArp;
	}
	
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
		return ip->dst.value() == ntohl(cmsg->leftA);
	}


	inline bool isRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
		return ip->dst.value() == ntohl(cmsg->rightA);
	}
	
	inline bool isReconfigPacket(Ipv4* ip, Tcp* tcp) {
		DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
		if(isTCPSYN(tcp, true)) {
			if(!cb_in) {
				uint32_t payload_len = hasPayload(ip, tcp);
				if(payload_len) {
					//Only LeftAnchor
					uint32_t tcp_hlen = tcp->offset << 2;
					if(((uint8_t*)tcp + tcp_hlen)[payload_len - 1] == 0xFF)
						return true;
				}
				
				return false;
			}
			
			return false;
		}

		if(!cb_in) {
			return false;
		}
		
		if((isTCPSYN(tcp) && isTCPACK(tcp)) || isTCPACK(tcp, true)) {
			if(cb_in->is_reconfiguration) {
				return true;
			}
		}

		return false;
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
	bool input(bess::Packet*, Ipv4*, Tcp*);


	/*
	  Control methods
	 */
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, Tcp*, DyscoControlMessage*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);
	CONTROL_RETURN control_reconfig_in(bess::Packet*, Ipv4*, Tcp*, uint8_t*, DyscoCbReconfig*, DyscoControlMessage*);
	CONTROL_RETURN control_input(bess::Packet*, Ipv4*, Tcp*);



	

	bool tcp_sack(Tcp*, DyscoHashIn*);

	/*

	 */

	void process_arp(bess::Packet*);
	void create_synack(bess::Packet*, Ipv4*, Tcp*);
	void create_ack(bess::Packet*, Ipv4*, Tcp*);
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
