#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>

#include "dysco_util.h"
#include "dysco_center.h"

class DyscoAgentOut final : public Module {
public:
	static uint64_t timeout;
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;
	
	DyscoAgentOut();
	
	//CommandResponse Init(const bess::pb::EmptyArg&);
	CommandResponse CommandSetup(const bess::pb::EmptyArg&);
	
	void ProcessBatch(PacketBatch*) override;
	bool forward(Packet*, bool = false);
	inline const char* getNs() {
		return ns.c_str();
	}
	
 private:
	string ns;
	thread* timer;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoVPort* port;

	/*
	  Dysco methods
	 */
	uint32_t out_rewrite_ts(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_seq(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_ack(Tcp*, DyscoHashOut*);
	bool output(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	DyscoHashOut* pick_path_ack(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_rcv_wnd(Tcp*, DyscoHashOut*);
	DyscoHashOut* pick_path_seq(DyscoHashOut*, uint32_t);
	void out_translate(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	
	/*
	  Dysco control methods
	 */
	void add_sc(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool output_mb(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool output_syn(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	void remove_tag(Packet*, Ipv4*, Tcp*);
	
	bool control_output(Ipv4*, Tcp*);
	bool control_insert_out(DyscoCbReconfig*);
	DyscoCbReconfig* insert_cb_control(Ipv4*, Tcp*, DyscoControlMessage*);
	
	/*
	  Auxiliary methods
	 */
	bool setup();
	void dysco_packet(Ethernet*);
	bool isReconfigPacketOut(Ipv4*, Tcp*, DyscoHashOut*);

	bool processLockingSignalPacket(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoHashOut*);
};

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
