#ifndef BESS_MODULES_DYSCOSYN_H_
#define BESS_MODULES_DYSCOSYN_H_

#include "../module.h"
#include "DyscoBPF.h"

class DyscoSyn final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  //static const gate_idx_t kNumOGates = 2;

  DyscoSyn();

  void ProcessBatch(bess::PacketBatch*) override;

 private:
  DyscoBPF* bpf;
};

#endif
