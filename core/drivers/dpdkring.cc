#include "dpdkring.h"

#include "../utils/ether.h"
#include "../utils/format.h"

CommandResponse DPDKRing::Init(const bess::pb::DPDKRingArg& arg) {
	_tx_ring = rte_ring_lookup(arg.tx_ring().c_str());
	if(!_tx_ring) {
		return CommandFailure(EINVAL, "Error to lookup the TX ring.");
	}

	_rx_ring = rte_ring_lookup(arg.rx_ring().c_str());
	if(!_rx_ring) {
		return CommandFailure(EINVAL, "Error to lookup the RX ring.");
	}
	
	_message_pool = rte_mempool_lookup(arg.mem_pool().c_str());
	if(!_message_pool) {
		return CommandFailure(EINVAL, "Error to lookup the mempool.");
	}
		
	return CommandSuccess();
}

void DPDKRing::DeInit() {

}

int DPDKRing::RecvPackets(queue_t, bess::Packet** pkts, int cnt) {
	unsigned int avail;
	
	return rte_ring_dequeue_burst(_rx_ring, (void**) pkts, cnt, &avail);
}

int DPDKRing::SendPackets(queue_t, bess::Packet** pkts, int cnt) {
	return rte_ring_enqueue_burst(_tx_ring, (void* const*) pkts, cnt, 0);
}

ADD_DRIVER(DPDKRing, "dpdkring", "DPDK Ring module driver")
