#ifndef BESS_DRIVERS_DYSCO_VPORT_H_
#define BESS_DRIVERS_DYSCO_VPORT_H_

#include <arpa/inet.h>

#include "../kmod/sn_common.h"
#include "../port.h"

class DyscoVPort final : public Port {
 public:
 DyscoVPort() : fd_(), bar_(), map_(), netns_fd_(), container_pid_() {}
	void InitDriver() override;
	
	CommandResponse Init(const bess::pb::DyscoVPortArg &arg);
	void DeInit() override;

	int RecvPackets(queue_t qid, bess::Packet **pkts, int max_cnt) override;
	int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

	//Dysco
	// private:
	struct queue {
		union {
			struct sn_rxq_registers *rx_regs;
		};
		
		struct llring *drv_to_sn;
		struct llring *sn_to_drv;
	};
	
	void FreeBar();
	void *AllocBar(struct tx_queue_opts *txq_opts,
		       struct rx_queue_opts *rxq_opts);
	int SetIPAddrSingle(const std::string &ip_addr);
	CommandResponse SetIPAddr(const bess::pb::DyscoVPortArg &arg);
	
	int fd_;
	
	char ifname_[IFNAMSIZ]; /* could be different from Name() */
	void *bar_;

	struct queue inc_qs_[MAX_QUEUES_PER_DIR];
	struct queue out_qs_[MAX_QUEUES_PER_DIR];

	struct sn_ioc_queue_mapping map_;

	int netns_fd_;
	int container_pid_;
	//Dysco
	uint32_t devip;
};

#endif  // BESS_DRIVERS_DYSCO_VPORT_H_
