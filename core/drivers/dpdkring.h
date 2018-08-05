#ifndef BESS_DRIVERS_DPDKRING_H_
#define BESS_DRIVERS_DPDKRING_H_

#include <string>

#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>

#include "../module.h"
#include "../port.h"

class DPDKRing final : public port {
 public:
	DPDKRing()
		: Port() {}

	CommandResponse Init(const bess::pb::DPDKRingArg&);
	void DeInit() override;
	int RecvPackets(queue_t, bess::Packet**, int) override;
	int SendPackets(queue_t, bess::Packet**, int) override;

 private:
	std::string _tx_ring;
	std::string _rx_ring;
	std::string _message_pool;
};

#endif // BESS_DRIVERS_DPDKRING_H_
