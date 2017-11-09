#ifndef BESS_MODULES_DYSCOPOLICYCENTER_H_
#define BESS_MODULES_DYSCOPOLICYCENTER_H_

#include <vector>
#include <rte_hash_crc.h>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

#include "../utils/cuckoo_map.h"
#include "../utils/endian."

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

Class DyscoTcpSession {
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

class DyscoControlBlock {
 private:
	struct tcp_session subss;
	struct tcp_session supss;

	uint8* sc;
	uint32_t sc_len;
};

class DyscoPolicyCenter final : public Module {
 public:
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	DyscoPolicyCenter();

	bool add(Ipv4*, Tcp*, uint8_t*, int);
 private:
	using HashTable = bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>;
};

#endif //BESS_MODULES_DYSCOPOLICYCENTER_H_
