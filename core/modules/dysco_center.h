#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include <vector>
#include <unordered_map>
#include <rte_hash_crc.h>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

#include "../utils/cuckoo_map.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

#include "dysco_policies.h"

using std::unordered_map;
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;
using bess::utils::be32_t;
using bess::utils::be16_t;

#define DYSCO_TCP_OPTION_LEN 8

enum {
	DYSCO_ONE_PATH = 0,
	DYSCO_ADDING_NEW_PATH,
	DYSCO_ACCEPTING_NEW_PATH,
	DYSCO_INITIALIZING_NEW_PATH,
	DYSCO_MANAGING_TWO_PATHS,
	DYSCO_FINISHING_OLD_PATH,
	DYSCO_UNLOCKED,
	DYSCO_LOCK_PENDING,
	DYSCO_LOCKED
};

class DyscoTcpSession {
 public:
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;

	bool operator==(const DyscoTcpSession& t) const {
		return sip == t.sip && sport == t.sport && dip == t.sip && dport == t.dport;
	}
};

class DyscoTcpSessionHash {
 public:
	std::size_t operator()(const DyscoTcpSession& t) const {
		return rte_hash_crc(&t, sizeof(uint64_t), 0);
	}	
};

class DyscoTcpSessionEqualTo {
 public:
	bool operator()(const DyscoTcpSession& a, const DyscoTcpSession& b) const {
		return a.sip == b.sip && a.dip == b.dip && a.sport == b.sport && a.dport == b.dport;
	}
};

class DyscoHashOut;

class DyscoHashIn {
 public:
	DyscoTcpSession sub;
	DyscoTcpSession sup;
	DyscoHashOut* cb_out;

	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	
	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	uint8_t two_paths:1,
		ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		tsr_add:1,
		ws_ok:1;
	uint8_t padding;
	
	uint32_t skb_iif;
};

class DyscoHashOut {
 public:
	DyscoHashIn* cb_in;
	DyscoTcpSession sub;
	DyscoTcpSession sup;

	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	uint32_t seq_cutoff;
	uint32_t ack_cutoff;
	//tcp_sock (my_tp, other_tp) ???
	uint32_t* sc;
	uint32_t sc_len;
	DyscoHashOut* other_path;

	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;
	uint32_t dysco_tag;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	//nh_mac ???
	uint8_t state;
	uint8_t old_path:1,
		valid_ack_cut:1,
		use_np_seq:1,
		use_np_ack:1,
		state_t:1,
		free_sc:1;
	uint8_t ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		ws_ok:1,
		tsr_add:1,
		tag_ok:1;
	uint8_t padding;
	
	uint32_t ack_ctr;
};

class DyscoHashPenTag {

};

class DyscoHashes {
 public:
	std::string ns;
	uint32_t index;
	uint32_t devip;

	DyscoPolicies policies;
	
	unordered_map<DyscoTcpSession, DyscoHashIn, DyscoTcpSessionHash> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash> hash_pen;
	unordered_map<DyscoTcpSession, DyscoHashPenTag, DyscoTcpSessionHash> hash_pen_tag;
};

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	
	DyscoCenter();

	CommandResponse CommandList(const bess::pb::EmptyArg&);
	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);

	uint32_t get_index(const std::string&, uint32_t);
	DyscoHashIn* lookup_input(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_output(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_output_pending(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_pending_tag(uint32_t, Ipv4*, Tcp*);

	DyscoHashIn* insert_cb_in(uint32_t, Ipv4*, Tcp*, uint8_t*, uint32_t);
	bool handle_mb_out(uint32_t, bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	DyscoHashOut* process_syn_out(uint32_t, bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);

	


 private:
	unordered_map<uint32_t, DyscoHashes> hashes;

	DyscoHashes* get_hash(uint32_t);

	bool insert_cb_out(uint32_t, DyscoHashOut*, uint8_t);
	DyscoHashIn* insert_cb_out_reverse(uint32_t, DyscoHashOut*, uint8_t);
	
	bool out_hdr_rewrite(Ipv4*, Tcp*, DyscoTcpSession*);
	bool remove_tag(bess::Packet*, Ipv4*, Tcp*);
	bool add_sc(bess::Packet*, Ipv4*, DyscoHashOut*);
	bool fix_tcp_ip_csum(Ipv4*, Tcp*);

	DyscoHashIn* lookup_input(uint32_t, DyscoTcpSession*);
	DyscoHashOut* insert_cb_in_reverse(DyscoTcpSession*, Ipv4*, Tcp*);
	bool parse_tcp_syn_opt_s(Tcp*, DyscoHashOut*);
	DyscoHashIn* lookup_input_by_ss(uint32_t, DyscoTcpSession*);

	
	inline bool isTCPACK(Tcp* tcp) {
		return tcp->flags == Tcp::Flag::kAck;
	}

	
	bool insert_pending(DyscoHashes*, uint8_t*, uint32_t);
	//DyscoHashOut* insert_cb_in_reverse(DyscoTcpSession*, Ipv4*, Tcp*);
	//DyscoHashIn* insert_cb_out_reverse(DyscoHashOut*);

	uint16_t allocate_local_port(uint32_t);
	uint16_t allocate_neighbor_port(uint32_t);


	
	bool process_pending_packet(uint32_t, bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);

	DyscoHashIn* insert_cb_in_reverse2(DyscoHashOut*);
};

#endif //BESS_MODULES_DYSCOCENTER_H_
