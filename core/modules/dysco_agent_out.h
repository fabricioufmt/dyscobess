#ifndef BESS_MODULES_DYSCOAGENTOUT_H_
#define BESS_MODULES_DYSCOAGENTOUT_H_

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>

#include "dysco_util.h"
#include "dysco_center.h"
#include "dysco_agent_in.h"

class DyscoAgentIn;

class DyscoAgentOut final : public Module {
public:
	mutex mtx;
	static uint64_t timeout;
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 1;
	static const gate_idx_t kNumOGates = 2;
	
	DyscoAgentOut();
	
	//CommandResponse Init(const bess::pb::EmptyArg&);
	CommandResponse CommandSetup(const bess::pb::DyscoAgentArg&);
	
	void ProcessBatch(PacketBatch*) override;
	bool forward(Packet*, bool = false);
	
	inline const char* getNs() {
		return ns.c_str();
	}

	LinkedList<Packet>* getRetransmissionList();

	LNode<Packet>* add(Packet&, uint64_t);
	void remove(LNode<Packet>*);
	
 private:
	string ns;
	thread* timer;
	uint32_t devip;
	uint32_t index;
	DyscoCenter* dc;
	DyscoVPort* port;
	DyscoAgentIn* agent;
	LinkedList<Packet>* retransmission_list;

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

inline LinkedList<Packet>* DyscoAgentOut::getRetransmissionList() {
	return retransmission_list;
}

inline LNode<Packet>* DyscoAgentOut::add(Packet& pkt, uint64_t ns) {
	mtx.lock();
	LNode<Packet>* node = retransmission_list->insertTail(pkt, ns);
	mtx.unlock();

	return node;
}

inline void DyscoAgentOut::remove(LNode<Packet>* node) {
	mtx.lock();
	retransmission_list->remove(node);
	mtx.unlock();
}

inline bool DyscoAgentOut::forward(Packet* pkt, bool reliable) {
	if(!reliable) {
		PacketBatch out;
		out.clear();
		out.add(pkt);
		RunChooseModule(1, &out);

		return true;
	}

	if(!timer)
		timer = new thread(timer_worker, this);

	mtx.lock();
	LNode<Packet>* node = retransmission_list->insertTail(*pkt, tsc_to_ns(rdtsc()));
	if(!node) {
		mtx.unlock();
		
		return false;
	}
	
	uint32_t i = getValueToAck(pkt);

	bool updated = agent->updateReceivedHash(i, node);

#ifdef DEBUG
	if(updated)
		fprintf(stderr, "I expected to received a packet with %X ACK\n", i);
#endif

	mtx.unlock();
	
	return updated;
}

#endif //BESS_MODULES_DYSCOAGENTOUT_H_
