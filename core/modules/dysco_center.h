#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include "dysco_util.h"

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	
	DyscoCenter();

	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);
	CommandResponse CommandList(const bess::pb::DyscoCenterListArg&);
	CommandResponse CommandAlarm(const bess::pb::EmptyArg&);

	/*
	  TCP methods
	*/
	bool after(uint32_t, uint32_t);
	bool before(uint32_t, uint32_t);
	DyscoTcpTs* get_ts_option(Tcp*);
	bool tcp_sack(Tcp*, uint32_t, uint8_t);
	bool parse_tcp_syn_opt_s(Tcp*, DyscoHashOut*);
	bool parse_tcp_syn_opt_r(Tcp*, DyscoHashIn*);


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
	bool remove_hash_reconfig(uint32_t, DyscoCbReconfig*);

	/*
	 * DyscoControl methods
	 */
	DyscoHashIn* insert_cb_input(uint32_t, Ipv4*, Tcp*, uint8_t*, uint32_t);


	
	uint16_t allocate_local_port(uint32_t);
	uint16_t allocate_neighbor_port(uint32_t);
	uint32_t get_index(string, uint32_t);
	
	
	bool insert_cb_out(uint32_t, DyscoHashOut*, uint8_t);
	bool set_ack_number_out(uint32_t, Tcp*, DyscoHashIn*);
	bool insert_tag(uint32_t, Packet*, Ipv4*, Tcp*);
	bool replace_cb_leftA(DyscoCbReconfig*, DyscoControlMessage*);

	bool out_hdr_rewrite(Packet*, Ipv4*, Tcp*, DyscoTcpSession*);

	bool out_handle_mb(uint32_t, Packet*, Ipv4*, Tcp*, DyscoHashOut*, uint32_t);
	bool out_syn(uint32_t, Packet*, Ipv4*, Tcp*, DyscoHashOut*, uint32_t);
	DyscoHashIn* insert_cb_out_reverse(uint32_t, DyscoHashOut*, uint8_t, DyscoControlMessage* = 0);
	

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
	uint32_t get_dysco_tag(uint32_t);
	bool remove_tag(Packet*, Ipv4*, Tcp*);
	void add_sc(Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool insert_pending(DyscoHashes*, uint8_t*, uint32_t);
	bool insert_pending_reconfig(DyscoHashes*, uint8_t*, uint32_t);
	DyscoHashOut* insert_cb_in_reverse(DyscoTcpSession*, Ipv4*, Tcp*);
	DyscoHashOut* create_cb_out(uint32_t, Ipv4*, Tcp*, DyscoPolicies::Filter*, uint32_t);

	inline bool isReconfigPacket(Ipv4* ip, Tcp* tcp) {
		if(isTCPSYN(tcp)) {
			uint32_t payload_len = hasPayload(ip, tcp);
			if(payload_len) {
				if(((uint8_t*)tcp + (tcp->offset << 2))[payload_len - 1] == 0xFF)
					return true;
				
				return false;
			}
		}

		return false;
	}
};

#endif //BESS_MODULES_DYSCOCENTER_H_
