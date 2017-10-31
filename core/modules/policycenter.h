#ifndef BESS_MODULES_BPF_H_
#define BESS_MODULES_BPF_H_

#include <pcap.h>
#include <vector>
#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/endian.h"

#include <rte_config.h>
#include <rte_hash_crc.h>


#include "../utils/cuckoo_map.h"
#include "../utils/endian.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

struct tcp_session {
  be32_t sip;
  be32_t dip;
  be16_t sport;
  be16_t dport;

  struct Hash {
    std::size_t operator()(const struct tcp_session& t) const {
      return rte_hash_crc(&t, sizeof(uint64_t), 0);
    }
  };

  struct EqualTo {
    bool operator()(const struct tcp_session& a, const struct tcp_session& b) const {
      return a.sip == b.sip && a.dip == b.dip && a.sport == b.sport && a.dport == b.dport;
    }
  };
};

struct dysco_cb {
  struct tcp_session subss;
  struct tcp_session supss;

  be32_t* sc;
  be32_t sclen;
};

class PolicyCenter final : public Module {
 public:
 PolicyCenter() : Module() {}
  static const gate_idx_t kNumIGates = 3;
  static const gate_idx_t kNumOGates = 1;
  
  uint8_t* get_payload(bess::Packet*);
  void remove_payload(bess::Packet*);
  struct tcp_session* find_mapping(bess::Packet*);
  void create_mapping(bess::Packet*, uint8_t*);
  void restore_syn_p(bess::Packet*);
  void restore_super_session(bess::Packet*);
  void ProcessBatch(bess::PacketBatch*) override;
  
 private:
  using HashTable = bess::utils::CuckooMap<struct tcp_session, struct dysco_cb, struct tcp_session::Hash, struct tcp_session::EqualTo>;
  HashTable map;
};

#endif
