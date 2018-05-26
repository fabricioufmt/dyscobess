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
	static uint64_t timeout;
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;

	DyscoAgentIn();
	
	void ProcessBatch(bess::PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	CommandResponse CommandSetup(const bess::pb::EmptyArg&);

	/*
	  TCP Retransmission methods
	*/
	void retransmissionHandler();
	bool processReceivedPacket(Tcp*);
	
 private:
	string ns;
	thread* timer;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoVPort* port;

	//For Retransmission Test
	uint32_t cnt;
	
	/*
	  Dysco methods
	 */
	bool tcp_sack(Tcp*, DyscoHashIn*); 
	void remove_sc(Packet*, Ipv4*, uint32_t);
	void in_hdr_rewrite(Ipv4*, Tcp*, DyscoTcpSession*);
	uint32_t in_rewrite_seq(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_ack(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_ts(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_rcv_wnd(Tcp*, DyscoHashIn*);
	bool in_hdr_rewrite_csum(Ipv4*, Tcp*, DyscoHashIn*);
	void rx_initiation_new(Packet*, Ipv4*, Tcp*);
	bool in_two_paths_ack(Tcp*, DyscoHashIn*);
	bool in_two_paths_data_seg(Tcp*, DyscoHashIn*);
	CONTROL_RETURN input(Packet*, Ipv4*, Tcp*, DyscoHashIn*);

	/*
	  Dysco control methods
	 */
	bool isReconfigPacket(Ipv4*, Tcp*, DyscoHashIn*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, Tcp*, DyscoControlMessage*);
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);
	CONTROL_RETURN control_reconfig_in(Packet*, Ipv4*, Tcp*, uint8_t*, DyscoCbReconfig*, DyscoControlMessage*);
	CONTROL_RETURN control_input(Packet*, Ipv4*, Tcp*, DyscoHashIn*);

	/*
	  Auxiliary methods
	 */
	bool setup();
	bool isEstablished(Packet*);
	void createAck(Packet*, Ipv4*, Tcp*);
	void createSynAck(Packet*, Ipv4*, Tcp*);
	void createFinAck(Packet*, Ipv4*, Tcp*);
};

#endif //BESS_MODULES_DYSCOAGENTIN_H_
