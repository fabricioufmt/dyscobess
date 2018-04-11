#include "etherswitch.h"

#include "../utils/endian.h"

const Commands EtherSwitch::cmds = {
	{"add", "EtherSwitchCommandAddArg", MODULE_CMD_FUNC(&EtherSwitch::CommandAdd),
	 Command::THREAD_UNSAFE},
	{"del", "EtherSwitchCommandDelArg", MODULE_CMD_FUNC(&EtherSwitch::CommandDel),
	 Command::THREAD_UNSAFE},
};

CommandResponse EtherSwitch::Init(const bess::pb::EtherSwitchArg&) {
	return CommandSuccess();
}

CommandResponse EtherSwitch::CommandAdd(const bess::pb::EtherSwitchCommandAddArg&) {
	//TODO
	return CommandSuccess();
}

CommandResponse EtherSwitch::CommandDel(const bess::pb::EtherSwitchCommandDelArg&) {
	//TODO
	return CommandSuccess();
}

bool EtherSwitch::isBroadcast(bess::Packet* pkt, gate_idx_t igate, gate_idx_t* ogate) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	
	_entries[eth->src_addr] = igate;
	
	auto search = _entries.find(eth->dst_addr);
	if(search != _entries.end()) {
		*ogate = search->second;
		return false;
	}

	return true;
}

void EtherSwitch::ProcessBatch(bess::PacketBatch* batch) {
	size_t ngates_;
	gate_idx_t ogate;
	gate_idx_t igate = get_igate();
	ngates_ = ogates().size();
	bess::PacketBatch out_gates[ngates_];
	
	for(uint32_t i = 0; i < ngates_; i++)
		out_gates[i].clear();

	bess::Packet* pkt;
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		if(isBroadcast(pkt, igate, &ogate)) {
			for(uint32_t j = 0; j < ngates_; j++) {
				if(j == igate)
					continue;
				out_gates[j].add(bess::Packet::copy(pkt));
			}
		} else
			out_gates[ogate].add(bess::Packet::copy(pkt));
	}

	for(uint32_t i = 0; i < ngates_; i++)
		RunChooseModule(i, &(out_gates[i]));
}

ADD_MODULE(EtherSwitch, "etherswitch", "ethernet switch learning switch")
