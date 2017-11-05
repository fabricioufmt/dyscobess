#ifndef BESS_MODULES_DYSCOSYNP_H_
#define BESS_MODULES_DYSCOSYNP_H_

#include "../module.h"

struct tcp_session {
  uint32_t sip;
  uint32_t dip;
  uint16_t sport;
  uint16_t dport;

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

class DyscoControlBlock {
 public:
  struct tcp_session subss;
  struct tcp_session supss;
  struct tcp_session nextss;

  uint32_t* sc;
  uint32_t sc_len;
};

class DyscoSynP final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  //static const gate_idx_t kNumOGates = 2;

  DyscoSynP();
  void ProcessBatch(bess::PacketBatch*) override;
};

#endif
