#include "update_mac.h"

CommandResponse UpdateMac::Init(const bess::pb::UpdateMacArg& arg) {
	mac_addr.FromString(arg.mac_addr());

	return CommandResponse();
}

void UpdateMac::ProcessBatch(bess::PacketBatch* batch) {
	Ethernet* eth;
	bess::Packet* pkt;
	
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();

		eth->dst_addr = mac_addr;
	}

	RunChooseModule(0, batch);
}

ADD_MODULE(UpdateMac, "update_mac", "changes destination MAC address")
