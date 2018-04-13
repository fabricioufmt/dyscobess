#include "l2fwd.h"

const Commands L2FWD::cmds = {
	{"add", "L2FWDCommandAddArg", MODULE_CMD_FUNC(&L2FWD::CommandAdd),
	 Command::THREAD_UNSAFE}
};

CommandResponse L2FWD::Init(const bess::pb::L2FWDArg&) {
	return CommandSuccess();
}

void L2FWD::DeInit() {
	_entries.clear();
}

CommandResponse L2FWD::CommandAdd(const bess::pb::L2FWDCommandAddArg& arg) {
	Ethernet::Address addr;
	addr.FromString(arg.mac_addr());
	gate_idx_t gate = arg.gate();

	_entries[addr] = gate;
	
	return CommandSuccess();
}

bool L2FWD::isBroadcast(Ethernet::Address mac_addr) {
	Ethernet::Address broadcast;
	broadcast.FromString("ff:ff:ff:ff:ff:ff");

	return mac_addr == broadcast;
}

bool L2FWD::isKnown(Ethernet::Address mac_addr) {
	return _entries.find(mac_addr) != _entries.end();
}

void L2FWD::ProcessBatch(bess::PacketBatch* batch) {
	gate_idx_t igate;
	size_t ngates = ogates().size();
	bess::PacketBatch out_gates[ngates];

	for(uint32_t i = 0; i < ngates; i++)
		out_gates[i].clear();

	Ethernet* eth;
	bess::Packet* pkt;
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();
		
		if(isBroadcast(eth->dst_addr)) {
			if(isKnown(eth->src_addr)) {
				igate = _entries[eth->src_addr];
				for(uint32_t j = 0; j < ngates; j++) {
					if(j == igate)
						continue;

					out_gates[j].add(bess::Packet::copy(pkt));
				}
			}
		} else {
			if(isKnown(eth->dst_addr))
				out_gates[_entries[eth->dst_addr]].add(bess::Packet::copy(pkt));
		}
			
	}

	batch->clear();
	for(uint32_t i = 0; i < ngates; i++)
		RunChooseModule(i, &(out_gates[i]));
}

ADD_MODULE(L2FWD, "l2fwd", "simple ethernet switch")
