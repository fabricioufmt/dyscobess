#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include "dysco_util.h"

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	
	DyscoCenter();
	/*
	 * BESS methods
	 */
	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);
	CommandResponse CommandList(const bess::pb::DyscoCenterListArg&);

	/*
	 * Lookup methods
	 */
	DyscoHashIn* lookup_input(uint32_t, Ipv4*, Tcp*);
	DyscoHashIn* lookup_input_by_ss(uint32_t, DyscoTcpSession*);
	DyscoHashOut* lookup_output(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_output_by_ss(uint32_t, DyscoTcpSession*);
	DyscoHashOut* lookup_output_pending(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_pending_tag(uint32_t, Tcp*);
	DyscoHashOut* lookup_pending_tag_by_tag(uint32_t, uint32_t);
	DyscoCbReconfig* lookup_reconfig_by_ss(uint32_t, DyscoTcpSession*);

	/*
	 * HashTable methods
	 */
	bool insert_hash_input(uint32_t, DyscoHashIn*);
	bool insert_hash_output(uint32_t, DyscoHashOut*);
	bool insert_hash_reconfig(uint32_t, DyscoCbReconfig*);
	bool insert_pending(uint32_t, DyscoHashOut*);
	bool insert_pending_reconfig(uint32_t, DyscoHashOut*);
	bool remove_hash_reconfig(uint32_t, DyscoCbReconfig*);
	bool remove_hash_pen(uint32_t, DyscoHashOut*);
	

	DyscoPolicies::Filter* match_policy(uint32_t, Packet*);
	uint16_t allocate_local_port(uint32_t);
	uint16_t allocate_neighbor_port(uint32_t);
	
	uint32_t get_index(string, uint32_t);
	uint32_t get_dysco_tag(uint32_t);	

	/*
	  TCP Retransmission methods
	 */
	mutex* getMutex(uint32_t, uint32_t);
	bool add_retransmission(uint32_t, uint32_t, Packet*);
	LinkedList<Packet>* getRetransmissionList(uint32_t, uint32_t);
	unordered_map<uint32_t, LNode<Packet>*>* getHashReceived(uint32_t, uint32_t);
	
 private:
	unordered_map<uint32_t, DyscoHashes*> hashes;
	
	DyscoHashes* get_hashes(uint32_t);
};

#endif //BESS_MODULES_DYSCOCENTER_H_
