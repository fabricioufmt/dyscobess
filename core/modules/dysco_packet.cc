#include "dysco_packet.h"

void DyscoPacket::ProcessBatch(bess::PacketBatch* batch) {
	bess::PacketBatch out_gates[2];

	out_gates[0].clear();
	out_gates[1].clear();

	Ethernet* eth;
	bess::Packet* pkt;
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();

		if(eth->dst_addr == mac_addr)
			out_gates[0].add(pkt);
		else
			out_gates[1].add(pkt);
	}

	batch->clear();
	RunChooseModule(0, &out_gates[0]);
	RunChooseModule(1, &out_gates[1]);
}

ADD_MODULE(DyscoPacket, "dysco_packet", "verifies if the packet is Dysco or not")
