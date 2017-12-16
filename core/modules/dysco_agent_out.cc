#include "dysco_agent_out.h"
#include "../module_graph.h"

char* printip2(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
}

bool DyscoAgentOut::insert_metadata(bess::Packet* pkt) {
	uint32_t* metadata = (uint32_t*) _ptr_attr_with_offset<uint8_t>(0, pkt);
	metadata[0] = index;
	
	return true;
}

CommandResponse DyscoAgentOut::Init(const bess::pb::DyscoAgentOutArg& arg) {
	if(!arg.dc().length())
		return CommandFailure(EINVAL, "'dc' must be given as string.");

	const auto& it = ModuleGraph::GetAllModules().find(arg.dc().c_str());
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found.", arg.dc().c_str());

	dc = reinterpret_cast<DyscoCenter*>(it->second);
	if(!dc)
		return CommandFailure(ENODEV, "DyscoCenter module is NULL.");
	/*
	const char* port_name = arg.port().c_str();
	//const auto& itt = PortBuilder::all_ports().find(port_name);
	const auto& itt = PortBuilder::all_ports().find(arg.port());
	if(itt == PortBuilder::all_ports().end()) {
		return CommandFailure(ENODEV, "Port %s not found", port_name);
	}

	index = dc->get_index(reinterpret_cast<Port*>(itt->second)->name());
	*/
	inet_pton(AF_INET, arg.ip().c_str(), &devip);
	index = dc->get_index(arg.ns(), devip);

	return CommandSuccess();
}

bool DyscoAgentOut::process_syn(bess::Packet* , Ipv4* , Tcp* ) {
	if(!dc)
		return false;
	return true;
}
/**
   TODO: Do nothing?
 */
bool DyscoAgentOut::process_synp(bess::Packet*, Ipv4*, Tcp*) {
	return true;
}

bool DyscoAgentOut::process_nonsyn(bess::Packet*, Ipv4* , Tcp* ) {
	if(!dc)
		return false;
	return true;
}

bool DyscoAgentOut::process_packet(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	
	fprintf(stderr, "%s(IN): %s:%u -> %s:%u\n",
		name().c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());

	DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
	if(!cb_out) {
		cb_out = dc->lookup_output_pen(this->index, ip, tcp);
		if(cb_out) {
			return dc->process_pending_packet(this->index, pkt, ip, tcp, cb_out);
		}
	}

	if(isTCPSYN(tcp)) {
		return dc->process_syn_out(this->index, pkt, ip, tcp, cb_out);
	}

	/*
	if(isTCPSYN(tcp)) {
		if(hasPayload(ip, tcp))
			process_synp(pkt, ip, tcp);
		else
			process_syn(pkt, ip, tcp);
	} else
		process_nonsyn(pkt, ip, tcp);
	
	fprintf(stderr, "%s(OUT): %s:%u -> %s:%u\n",
		name().c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());
	*/
	return true;
}

void DyscoAgentOut::ProcessBatch(bess::PacketBatch* batch) {
	if(dc) {
		int cnt = batch->cnt();
		
		bess::Packet* pkt = 0;
		for(int i = 0; i < cnt; i++) {
			pkt = batch->pkts()[i];
			process_packet(pkt);
			insert_metadata(pkt);
		}
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming from host")
