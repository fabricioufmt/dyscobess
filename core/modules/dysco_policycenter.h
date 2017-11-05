#ifndef BESS_MODULES_DYSCOPOLICYCENTER_H_
#define BESS_MODULES_DYSCOPOLICYCENTER_H_

class DyscoPolicyCenter final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 3;
  DyscoPolicyCenter();

  void ProcessBatch(bess::PacketBatch*) override;
};

#endif
