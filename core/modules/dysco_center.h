#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include <map>
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

#define DYSCO_TCP_OPTION 253
#define DYSCO_TCP_OPTION_LEN 8
#define TCPOLEN_SACK_BASE 2
#define TCPOLEN_SACK_PERBLOCK 8

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

#define DYSCO_SYN_SENT			DYSCO_ADDING_NEW_PATH
#define DYSCO_SYN_RECEIVED		DYSCO_ACCEPTING_NEW_PATH
#define DYSCO_ESTABLISHED		DYSCO_INITIALIZING_NEW_PATH


enum {
	// Locking protocol
	DYSCO_REQUEST_LOCK = 1,
	DYSCO_ACK_LOCK,
	DYSCO_NACK_LOCK,
	
	// Reconfiguration
	DYSCO_SYN,
	DYSCO_SYN_ACK,
	DYSCO_ACK,
	DYSCO_FIN,
	DYSCO_FIN_ACK,
	
	// Management
	DYSCO_POLICY,
	DYSCO_REM_POLICY,
	DYSCO_CLEAR,
	DYSCO_CLEAR_ALL,
	DYSCO_BUFFER_PACKET,
	DYSCO_TCP_SPLICE,
	DYSCO_COPY_STATE,
	DYSCO_PUT_STATE,
	DYSCO_STATE_TRANSFERRED,
	DYSCO_ACK_ACK,
	DYSCO_GET_MAPPING,
	DYSCO_GET_REC_TIME
};

#define NOSTATE_TRANSFER	0
#define STATE_TRANSFER		1

class DyscoHeader {
 public:
	uint8_t operation;
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

class DyscoTcpOption {
 public:
	uint8_t kind;
	uint8_t len;
	uint16_t padding;
	uint32_t tag;
};

class DyscoTcpTs {
 public:
	uint32_t ts;
	uint32_t tsr;
};

class DyscoHashOut;

class DyscoHashIn {
 public:
	DyscoTcpSession sub;
	DyscoTcpSession sup;
	DyscoHashOut* dcb_out;

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
	DyscoHashIn* dcb_in;
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

class DyscoCbReconfig {
 public:
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	DyscoTcpSession sub_out;
	DyscoTcpSession sub_in;

	DyscoHashOut* old_dcb;
	DyscoHashOut* new_dcb;

	//Ronaldo:
	//timespec rec_begin, rec_end

	uint32_t leftIseq;
	uint32_t leftIack;
	uint32_t leftIts;
	uint32_t leftItsr;
	uint16_t leftIws;
	uint16_t leftIwsr;

	//Ronaldo:
	//uint_8 nh_mac[6]

	uint8_t sack_ok;
};

class DyscoControlMessage {
 public:
	uint32_t mtype;
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	uint32_t leftA;
	uint32_t rightA;

	uint16_t sport;
	uint16_t dport;

	uint32_t leftIseq;
	uint32_t leftIack;

	uint32_t rightIseq;
	uint32_t rightIack;

	uint32_t seqCutoff;

	uint32_t leftIts;
	uint32_t leftItsr;

	uint16_t leftIws;
	uint16_t leftIwsr;

	uint16_t sackOk;
	uint16_t semantic;

	uint32_t srcMB;
	uint32_t dstMB;
};

class DyscoHashes {
 public:
	uint32_t index;
	uint32_t devip;
	std::string ns;
	
	DyscoPolicies policies;
	uint32_t dysco_tag;
	
	unordered_map<DyscoTcpSession, DyscoHashIn, DyscoTcpSessionHash> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash> hash_pen;
	unordered_map<uint32_t, DyscoHashOut> hash_pen_tag;

	unordered_map<DyscoTcpSession, DyscoCbReconfig, DyscoTcpSessionHash> hash_reconfig;
};

struct arp_entry {
	Ethernet::Address mac_addr;
	be32_t ip_addr;
};

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	
	DyscoCenter();

	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);
	CommandResponse CommandList(const bess::pb::DyscoCenterListArg&);
	//CommandResponse CommandReconfig(const bess::pb::DyscoCenterReconfigArg&);

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
	  Control methods
	*/
	uint32_t get_index(std::string, uint32_t);
	DyscoHashIn* lookup_input(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_output(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_output_by_ss(uint32_t, DyscoTcpSession*);
	DyscoHashOut* lookup_output_pending(uint32_t, Ipv4*, Tcp*);
	DyscoHashOut* lookup_pending_tag(uint32_t, Tcp*);
	
	DyscoCbReconfig* lookup_reconfig_by_ss(uint32_t, DyscoTcpSession*);
	bool insert_hash_reconfig(uint32_t, DyscoCbReconfig*);
	bool insert_hash_input(uint32_t, DyscoHashIn*);
	bool insert_hash_output(uint32_t, DyscoHashOut*);
	bool remove_reconfig(uint32_t, DyscoCbReconfig*);
	bool replace_cb_leftA(DyscoCbReconfig*, DyscoControlMessage*);
	uint16_t allocate_local_port(uint32_t);
	uint16_t allocate_neighbor_port(uint32_t);
	
	/*
	  Dysco methods (INPUT)
	*/
	DyscoHashIn* insert_cb_input(uint32_t, Ipv4*, Tcp*, uint8_t*, uint32_t);
	bool set_ack_number_out(uint32_t, Tcp*, DyscoHashIn*);
	bool insert_tag(uint32_t, bess::Packet*, Ipv4*, Tcp*);
	DyscoHashIn* insert_cb_out_reverse(uint32_t, DyscoHashOut*, uint8_t);
	
	/*
	  Dysco methods (OUTPUT)
	*/
	DyscoHashOut* out_syn(uint32_t, bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*, uint32_t);
	bool out_handle_mb(uint32_t, bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*, uint32_t);
	bool out_hdr_rewrite(Ipv4*, Tcp*, DyscoTcpSession*);
	bool insert_cb_out(uint32_t, DyscoHashOut*, uint8_t);

	/*

	 */
	void update_mac(Ethernet::Address, be32_t);
	char* get_mac(be32_t);
	
 private:
	std::map<be32_t, struct arp_entry> entries;
	unordered_map<uint32_t, DyscoHashes> hashes;
	
	inline bool isTCPACK(Tcp* tcp) {
		return tcp->flags == Tcp::Flag::kAck;
	}
	
	/*
	  TCP methods
	*/
	bool fix_tcp_ip_csum(Ipv4*, Tcp*);
	
	/*
	  Control methods
	*/
	DyscoHashes* get_hash(uint32_t);
	uint32_t get_dysco_tag(uint32_t);	
	DyscoHashIn* lookup_input_by_ss(uint32_t, DyscoTcpSession*);
	DyscoHashOut* lookup_pending_tag_by_tag(uint32_t, uint32_t);

	/*
	  Dysco methods (INPUT)
	*/
	bool insert_pending(DyscoHashes*, uint8_t*, uint32_t);
	DyscoHashOut* insert_cb_in_reverse(DyscoTcpSession*, Ipv4*, Tcp*);

	/*
	  Dysco methods (OUTPUT)
	*/
	DyscoHashOut* create_cb_out(uint32_t, Ipv4*, Tcp*, DyscoPolicies::Filter*, uint32_t);
	bool out_tx_init(bess::Packet*, Ipv4*, Tcp*, DyscoHashOut*);
	bool remove_tag(bess::Packet*, Ipv4*, Tcp*);
	bool add_sc(bess::Packet*, Ipv4*, DyscoHashOut*);
};

#endif //BESS_MODULES_DYSCOCENTER_H_
