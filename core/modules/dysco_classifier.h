#ifndef BESS_MODULES_DYSCOCLASSIFIER_H_
#define BESS_MODULES_DYSCOCLASSIFIER_H_

#include <pcap.h>

#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_bpf.h"

class DyscoClassifier final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 4;
  
  DyscoClassifier() : Module() {
    bpf = new DyscoBPF();
    bpf->add_filter(1, "ip and tcp", 0, 0);
  }
  
  void ProcessBatch(bess::PacketBatch*) override;
 private:
  DyscoBPF* bpf;
};

#endif // BESS_MODULES_DYSCOCLASSIFIER_H_
