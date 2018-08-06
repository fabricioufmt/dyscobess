#ifndef BESS_DRIVERS_DPDKRING_H_
#define BESS_DRIVERS_DPDKRING_H_

#include <string>

#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>

#include "../module.h"
#include "../port.h"

class DPDKRing final : public Port {
 public:
	DPDKRing()
		: Port() {}

	CommandResponse Init(const bess::pb::DPDKRingArg&);
	void DeInit();
	int RecvPackets(queue_t, bess::Packet**, int);
	int SendPackets(queue_t, bess::Packet**, int);

 private:
	struct rte_ring* _tx_ring;
	struct rte_ring* _rx_ring;
	struct rte_mempool* _message_pool;
};

#endif // BESS_DRIVERS_DPDKRING_H_
