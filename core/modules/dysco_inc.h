#ifndef BESS_MODULES_DYSCOINC_H_
#define BESS_MODULES_DYSCOIN_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"

class DyscoInc final : public Module {
 public:
  static const gate_idx_t kNumIGates = 0;

  static const Commands cmds;

  DyscoInc() : Module(), port_(), prefetch_(), burst_() {
    is_task_ = true;
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::PortIncArg &arg);

  void DeInit() override;

  struct task_result RunTask(void *arg) override;

  std::string GetDesc() const override;

  CommandResponse CommandSetBurst(
      const bess::pb::PortIncCommandSetBurstArg &arg);

 private:
  Port *port_;
  int prefetch_;
  int burst_;
};

#endif  // BESS_MODULES_DYSCOINC_H_
