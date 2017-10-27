#ifndef BESS_MODULES_BPF_H_
#define BESS_MODULES_BPF_H_

#include <pcap.h>
#include <vector>
#include "../module.h"
#include "../pb/module_msg.pb.h"

class SynClassifier final : public Module {
 public:
  static const gate_idx_t kNumOGates = 3;
  SynClassifier() : Module() {}
  void ProcessBatch(bess::PacketBatch*) override;
};

#endif
