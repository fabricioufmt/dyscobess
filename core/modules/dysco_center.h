#ifndef BESS_MODULES_DYSCOCENTER_H_
#define BESS_MODULES_DYSCOCENTER_H_

#include <vector>
#include <rte_hash_crc.h>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

#include "../utils/cuckoo_map.h"
#include "../utils/endian.h"

#include "dysco_bpf.h"

using std::map;
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

class DyscoTcpSession {
 public:
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;

	struct Hash {
		std::size_t operator()(const DyscoTcpSession& t) const {
			return rte_hash_crc(&t, sizeof(uint64_t), 0);
		}
	};

	struct EqualTo {
		bool operator()(const DyscoTcpSession& a, const DyscoTcpSession& b) const {
			return a.sip == b.sip && a.dip == b.dip && a.sport == b.sport && a.dport == b.dport;
		}
	};
};

class DyscoHashOut;

class DyscoHashIn {
 private:
	DyscoHashOut* cb_out;
	DyscoTcpSession sub;
	DyscoTcpSession sup;
	
 public:
	void set_cb_out(DyscoHashOut* cb) {
		this->cb_out = cb;
	}
	
	DyscoTcpSession* get_sub() {
		return &sub;
	}
	
	DyscoTcpSession* get_sup() {
		return &sup;
	}
};

class DyscoHashOut {
 private:
	DyscoHashIn* cb_in;
	DyscoTcpSession sub;
	DyscoTcpSession sup;

	uint32_t* sc;
	uint32_t sc_len;
	
 public:
	void set_sc_len(uint32_t len) {
		this->sc_len = len;
	}
	
	void set_cb_in(DyscoHashIn* cb) {
		this->cb_in = cb;
	}
	
	DyscoTcpSession* get_sub() {
		return &sub;
	}
	
	DyscoTcpSession* get_sup() {
		return &sup;
	}

	uint32_t* get_sc() {
		return sc;
	}
};

class DyscoHashPenTag {

};

class DyscoHashes {
 public:
	uint32_t index;
	
	map<DyscoTcpSession, DyscoHashIn, DyscoTcpSession::EqualTo> hash_in;
	map<DyscoTcpSession, DyscoHashOut, DyscoTcpSession::EqualTo> hash_out;
	map<DyscoTcpSession, DyscoHashOut, DyscoTcpSession::EqualTo> hash_pen;
	map<DyscoTcpSession, DyscoHashPenTag, DyscoTcpSession::EqualTo> hash_pen_tag;
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


	uint32_t get_index(const std::string&);
	DyscoHashIn* lookup_input(uint32_t, Ipv4*, Tcp*);
	DyscoHashIn* insert_cb_in(uint32_t, Ipv4*, Tcp*, uint8_t*, uint32_t);
	
 private:
	map<uint32_t, DyscoHashes> hashes;

	DyscoHashes* get_hash(uint32_t);
	bool insert_pending(DyscoHashes*, uint8_t*, uint32_t);
	DyscoHashOut* insert_cb_in_reverse(DyscoTcpSession*, Ipv4*, Tcp*);
};

#endif //BESS_MODULES_DYSCOCENTER_H_
