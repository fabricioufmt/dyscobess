#ifndef BESS_MODULES_DYSCOSYNP_H_
#define BESS_MODULES_DYSCOSYNP_H_

#include "../module.h"

class DyscoSynP final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  //static const gate_idx_t kNumOGates = 2;

  DyscoSynP();

  void ProcessBatch(bess::PacketBatch*) override;
};

#endif
