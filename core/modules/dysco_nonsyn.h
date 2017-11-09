#ifndef BESS_MODULES_DYSCONONSYN_H_
#define BESS_MODULES_DYSCONONSYN_H_

#include "../module.h"

class DyscoNonSyn final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  //static const gate_idx_t kNumOGates = 2;

  DyscoNonSyn();

  void ProcessBatch(bess::PacketBatch*) override;
};

#endif //BESS_MODULES_DYSCONONSYN_H_
