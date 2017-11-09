#ifndef BESS_MODULES_DYSCOOUT_H_
#define BESS_MODULES_DYSCOOUT_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"
#include "../worker.h"

class DyscoOut final : public Module {
 public:
	static const gate_idx_t kNumIGates = MAX_GATES;
	static const gate_idx_t kNumOGates = 0;
	
 DyscoOut() : Module(), port_(), available_queues_(), worker_queues_() {}
	
	CommandResponse Init(const bess::pb::DyscoOutArg &arg);
	
	void DeInit() override;
	
	void ProcessBatch(bess::PacketBatch *batch) override;
	
	int OnEvent(bess::Event e) override;
	
	std::string GetDesc() const override;
	
 private:
	Port *port_;
	
	std::vector<queue_t> available_queues_;
	
	int worker_queues_[Worker::kMaxWorkers];
};

#endif  // BESS_MODULES_DYSCOOUT_H_
