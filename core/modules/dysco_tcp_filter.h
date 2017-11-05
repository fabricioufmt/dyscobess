#ifndef BESS_MODULES_DYSCOTCPFILTER_H_
#define BESS_MODULES_DYSCOTCPFILTER_H_

#include <pcap.h>

#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "dysco_bpf.h"

class DyscoTcpFilter final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 2;
  
  //DyscoTcpFilter() : Module() {}
  
  void ProcessBatch(bess::PacketBatch*) override;
 private:
  DyscoBPF* bpf;
};

#endif // BESS_MODULES_DYSCOTCPFILTER_H_
