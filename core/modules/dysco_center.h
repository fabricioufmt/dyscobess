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

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

class DyscoTcpSession {
 public:
	uint32_t i;
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
			return a.i == b.i && a.sip == b.sip && a.dip == b.dip && a.sport == b.sport && a.dport == b.dport;
		}
	};
};

class DyscoControlBlock {
 public:
	DyscoTcpSession subss;
	DyscoTcpSession supss;
	DyscoTcpSession nextss;

	uint8_t* sc;
	uint32_t sc_len;
};

class DyscoCenter final : public Module {
 public:
	static const Commands cmds;
	
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	DyscoCenter();

	bool add_mapping(uint32_t, Ipv4*, Tcp*, uint8_t*, uint32_t);
	DyscoControlBlock* add_mapping_filter(uint32_t, Ipv4*, Tcp*, DyscoBPF::Filter*);
	//bool add_mapping(Ipv4*, Tcp*, uint8_t*, uint32_t);
	//DyscoControlBlock* add_mapping_filter(Ipv4*, Tcp*, DyscoBPF::Filter*);
	bool add_policy_rule(uint32_t, std::string, uint8_t*, uint32_t);
	DyscoControlBlock* get_controlblock_by_subss(uint32_t, Ipv4*, Tcp*);
	DyscoControlBlock* get_controlblock_by_supss(uint32_t, Ipv4*, Tcp*);
	//DyscoControlBlock* get_controlblock(uint32_t, Ipv4*, Tcp*);
	//DyscoControlBlock* get_controlblock(Ipv4*, Tcp*);
	//DyscoControlBlock* get_controlblock_supss(Ipv4*, Tcp*);
	
	uint32_t get_index(const std::string&);
	bool add_backmapping(uint32_t, DyscoControlBlock*);
	DyscoTcpSession* get_subss_by_supss(uint32_t, Ipv4*, Tcp*);
	DyscoTcpSession* get_supss_by_subss(uint32_t, Ipv4*, Tcp*);
	//DyscoTcpSession* get_subss(Ipv4*, Tcp*);
	//DyscoTcpSession* get_supss(Ipv4*, Tcp*);
	//DyscoTcpSession* get_nextss(Ipv4*, Tcp*);
	DyscoBPF::Filter* get_filter(bess::Packet*);
	CommandResponse CommandAdd(const bess::pb::DyscoCenterAddArg&);
	CommandResponse CommandDel(const bess::pb::DyscoCenterDelArg&);
	CommandResponse CommandList(const bess::pb::EmptyArg&);
	
 private:
	using HashTable = bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>;
	//using HashTable = bess::utils::CuckooMap<uint32_t, bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>>;
	HashTable map;
	DyscoBPF* bpf;
};

#endif //BESS_MODULES_DYSCOCENTER_H_
