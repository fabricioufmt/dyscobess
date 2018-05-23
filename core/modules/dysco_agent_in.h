#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "dysco_center.h"

#include "../port.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/dysco_vport.h"

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
	static timeout = 1000000; //Default value
	DyscoAgentIn();
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	CommandResponse CommandInfo(const bess::pb::EmptyArg&);
	/*
	static void callHandlers(int) {
		std::for_each(instances.begin(), instances.end(), std::mem_fun(&DyscoAgentIn::retransmissionHandler));
	}
	*/

	/*
	  TCP Retransmission methods
	*/
	void retransmissionHandler();
	bool processReceivedPackets(Ipv4*, Tcp*);
	
 private:
	thread* timer;
	uint32_t devip;
	uint32_t index;
	std::string ns;
	DyscoCenter* dc;
	uint32_t timeout;
	DyscoVPort* port;
	//static std::vector<DyscoAgentIn*> instances;

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
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
