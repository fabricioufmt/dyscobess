#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include "dysco_util.h"
#include "dysco_center.h"

#define DYSCO_MAC "00:00:00:00:00:00"

class DyscoAgentOut final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;

	DyscoAgentOut();

	void ProcessBatch(PacketBatch*) override;
	CommandResponse Init(const bess::pb::DyscoAgentOutArg&);
	CommandResponse CommandSetup(const bess::pb::EmptyArg&);

 private:
	string ns;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoVPort* port;

	/*
	  Dysco methods
	 */
	uint32_t out_rewrite_seq(Tcp*, DyscoHashOut*);
	uint32_t out_rewrite_ack(Tcp*, DyscoHashOut*);
	bool out_rewrite_ts(Tcp*, DyscoHashOut*);
	bool out_rewrite_rcv_wnd(Tcp*, DyscoHashOut*);
	DyscoHashOut* pick_path_seq(DyscoHashOut*, uint32_t);
	DyscoHashOut* pick_path_ack(Tcp*, DyscoHashOut*);
	bool out_translate(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool update_five_tuple(Ipv4*, Tcp*, DyscoHashOut*);
	bool output(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	
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
	bool setup();
	void dysco_packet(Ethernet*);
	bool isReconfigPacketOut(Ipv4*, Tcp*, DyscoHashOut*);
};

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
