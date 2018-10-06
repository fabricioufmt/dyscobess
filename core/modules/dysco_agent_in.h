#ifndef BESS_MODULES_DYSCOAGENTIN_H_
#define BESS_MODULES_DYSCOAGENTIN_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>

#include "dysco_util.h"
#include "dysco_center.h"
#include "dysco_agent_out.h"

enum CONTROL_RETURN {
	TO_GATE_0,
	TO_GATE_1,
	IS_RETRANSMISSION,
	MIDDLE,
	ERROR,
	END,

	//Locking
	NONE,
	LOCK_SUCCESSFUL,
};

class DyscoAgentOut;

class DyscoAgentIn final : public Module {
 public:
	static uint64_t timeout;
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 1;

	DyscoAgentIn();
	
	void ProcessBatch(bess::PacketBatch*) override;
	//CommandResponse Init(const bess::pb::DyscoAgentInArg&);
	CommandResponse CommandSetup(const bess::pb::DyscoAgentArg&);

	bool updateReceivedHash(uint32_t, LNode<Packet>*);
	
 private:
	mutex mtx;
	string ns;
	thread* timer;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoVPort* port;
	DyscoAgentOut* agent;
	unordered_map<uint32_t, LNode<Packet>*>* received_hash;

	/*
	  Dysco methods
	 */
	bool tcp_sack(Tcp*, DyscoHashIn*);
	
	void remove_sc(Packet*, Ipv4*, uint32_t);
	uint32_t in_rewrite_seq(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_ack(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_ts(Tcp*, DyscoHashIn*);
	uint32_t in_rewrite_rcv_wnd(Tcp*, DyscoHashIn*);
	void in_hdr_rewrite_csum(Ipv4*, Tcp*, DyscoHashIn*);
	bool rx_initiation_new(Packet*, Ipv4*, Tcp*, uint32_t);
	
	bool in_two_paths_ack(Tcp*, DyscoHashIn*);
	bool in_two_paths_data_seg(Tcp*, DyscoHashIn*, uint32_t);
	bool input(Packet*, Ipv4*, Tcp*, DyscoHashIn*);
	bool set_ack_number_out(Tcp*, DyscoHashIn*);
	void insert_tag(Packet*, Ipv4*, Tcp*);

	DyscoHashOut* insert_cb_in_reverse(DyscoHashIn*, Ipv4*, Tcp*);
	
	/*
	  Dysco control methods
	 */
	bool isReconfigPacket(Ipv4*, Tcp*, DyscoHashIn*);
	DyscoHashOut* build_cb_in_reverse(Ipv4*, DyscoCbReconfig*);
	DyscoCbReconfig* insert_rcb_control_input(Ipv4*, Tcp*, DyscoControlMessage*);
	bool compute_deltas_in(DyscoHashIn*, DyscoHashOut*, DyscoCbReconfig*);
	bool compute_deltas_out(DyscoHashOut*, DyscoHashOut*, DyscoCbReconfig*);
	bool control_config_rightA(DyscoCbReconfig*, DyscoControlMessage*, DyscoHashIn*, DyscoHashOut*);
	bool control_reconfig_in(Packet*, Ethernet*, Ipv4*, Tcp*, uint8_t*, DyscoCbReconfig*, DyscoControlMessage*);
	bool control_input(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoHashIn*);

	/*
	  Auxiliary methods
	 */
	bool setup();
	bool isEstablished(Packet*);
	void createAck(Packet*, Ethernet*, Ipv4*, Tcp*);
	void createSynAck(Packet*, Ethernet*, Ipv4*, Tcp*, uint32_t);
	void createFinAck(Packet*, Ipv4*, Tcp*);

	/*
	 * Locking Signal methods
	 */
	Packet* processLockingSignalPacket(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoHashIn*);
	Packet* createLockingPacket(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoTcpOption*, DyscoHashIn*);
	bool createAckLockingSignalPacket(Packet*, Ethernet*, Ipv4*, Tcp*);
	
	/*
	 * Locking methods
	 */
	Packet* processLockingPacket(Packet*, Ethernet*, Ipv4*, Tcp*);
	Packet* processRequestLocking(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoControlMessage*, DyscoHashIn*);
	Packet* processAckLocking(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoControlMessage*, DyscoHashIn*);
	void createAckLocking(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoControlMessage*, DyscoHashOut*);

	/*
	 * Reconfig methods
	 */
	Packet* createSynReconfig(Packet*, Ethernet*, Ipv4*, Tcp*, DyscoControlMessage*);

	bool processReceivedPacket(Tcp*);
};

inline bool DyscoAgentIn::updateReceivedHash(uint32_t i, LNode<Packet>* node) {
	if(!received_hash)
		return false;
	
	mtx.lock();
	received_hash->operator[](i) = node;
	mtx.unlock();

	return true;
}

#endif //BESS_MODULES_DYSCOAGENTIN_H_
