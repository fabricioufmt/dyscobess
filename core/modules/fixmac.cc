#include "fixmac.h"

const Commands FixMac::cmds = {
    {"add", "FixMacCommandAddArg", MODULE_CMD_FUNC(&FixMac::CommandAdd),
     Command::THREAD_UNSAFE}};

CommandResponse FixMac::Init(const bess::pb::FixMacArg& arg) {
	ngates = arg.gates();

	return CommandResponse();
}

CommandResponse FixMac::CommandAdd(const bess::pb::FixMacCommandAddArg& arg) {
	Ethernet::Address mac_addr;
	mac_addr.FromString(arg.mac_addr());
	
	be32_t ip_addr;
	bess::utils::ParseIpv4Address(arg.ip_addr(), &ip_addr);

	gate_idx_t gate = arg.gate();
	
	struct mac_entry entry;
	entry.addr = mac_addr;
	entry.gate = gate;
	
	_entries[ip_addr] = entry;

	return CommandResponse();
}

bool FixMac::isBroadcast(Ethernet::Address dst_addr) {
	Ethernet::Address broadcast;
	broadcast.FromString("ff:ff:ff:ff:ff:ff");

	return dst_addr == broadcast;
}

bool FixMac::forward_mac(Ethernet* eth, gate_idx_t* ogate) {
	//bool flag = false;
	//gate_idx_t igate = 0;
	Ethernet::Address src_addr = eth->src_addr;
	//Ethernet::Address dst_addr = eth->dst_addr;

	for(auto it = _entries.begin(); it != _entries.end(); it++) {
		if(it->second.addr == src_addr) {
			*ogate = it->second.gate;

			return true;
		}
	}
	
	/*
	for(auto it = _entries.begin(); it != _entries.end(); it++) {
		if(it->second.addr == dst_addr) {
			*ogate = it->second.gate;
			
			return true;
		}
		//Just for Broadcast case
		if(it->second.addr == src_addr) {
			igate = it->second.gate;
			flag = true;
		}
	}

	//TEST
	if(isBroadcast(dst_addr) && flag) {
		*ogate = igate;
		fprintf(stderr, "is broadcast sending on %u gate\n", igate);
		return true; 
	}
	*/
	return false;
}

bool FixMac::forward(bess::Packet* pkt, gate_idx_t* ogate) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return forward_mac(eth, ogate);

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	
	auto search = _entries.find(ip->dst);
	if(search == _entries.end()) {
		fprintf(stderr, "ip->dst not found\n");
		return false;
	}
	eth->dst_addr = search->second.addr;
	
	/*
	search = _entries.find(ip->src);
	if(search == _entries.end())
		return false;
	
	*ogate = search->second.gate;
	return true;
	*/
	for(auto it = _entries.begin(); it != _entries.end(); it++) {
		if(it->second.addr == eth->src_addr) {
			*ogate = it->second.gate;

			fprintf(stderr, "src_addr found at %u\n", *ogate);
			
			return true;
		}
	}

	fprintf(stderr, "forward returns false\n");
	
	return false;
}

void FixMac::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();
	bess::PacketBatch out_gates[ngates];

	for(uint32_t i = 0; i < ngates; i++)
		out_gates[i].clear();

	gate_idx_t ogate;
	bess::Packet* pkt;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		if(forward(pkt, &ogate))
			out_gates[ogate].add(pkt);
	}

	for(uint32_t i = 0; i < ngates; i++)
		RunChooseModule(i, &(out_gates[i]));
}

ADD_MODULE(FixMac, "fixmac", "adjusts Ethernet Destination Address and forwards packets")
