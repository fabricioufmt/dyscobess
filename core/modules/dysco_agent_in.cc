#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"

char* printip1(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
}

CommandResponse DyscoAgentIn::Init(const bess::pb::DyscoAgentInArg& arg) {
	if(!arg.dc().length())
		return CommandFailure(EINVAL, "'dc' must be given as string.");

	const auto& it = ModuleGraph::GetAllModules().find(arg.dc().c_str());
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found.", arg.dc().c_str());

	dc = reinterpret_cast<DyscoCenter*>(it->second);
	if(!dc)
		return CommandFailure(ENODEV, "DyscoCenter module is NULL.");
	
	inet_pton(AF_INET, arg.ip().c_str(), &devip);
	index = dc->get_index(arg.ns(), devip);
	ns = arg.ns();
	
	return CommandSuccess();
}

bool DyscoAgentIn::parse_tcp_syn_opt_r(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_in->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			switch(opsize) {
			case TCPOPT_WINDOW:
				if(opsize == TCPOLEN_WINDOW) {
					uint8_t snd_wscale = *(uint8_t*)ptr;
					
					cb_in->ws_ok = 1;
					cb_in->ws_delta = 0;
					if (snd_wscale > 14)
						snd_wscale = 14;
					
					cb_in->ws_in = cb_in->ws_out = snd_wscale;
				}
				
				break;
				
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP) {
					if(tcp->flags & Tcp::kAck) {
						uint32_t ts, tsr;
						
						cb_in->ts_ok = 1;
						//ts = reinterpret_cast<uint32_t>(ptr);
						//tsr = reinterpret_cast<uint32_t>(ptr + 4);
						ts = (uint32_t)(*ptr);
						tsr = (uint32_t)(*(ptr + 4));
						cb_in->ts_in = cb_in->ts_out = ts;
						cb_in->tsr_in = cb_in->tsr_out = tsr;
						
						cb_in->ts_delta = cb_in->tsr_delta = 0;
					}
				}
				
				break;
				
			case TCPOPT_SACK_PERMITTED:
				if(opsize == TCPOLEN_SACK_PERMITTED)
					cb_in->sack_ok = 1;
				
				break;

			ptr += opsize - 2;
			len -= opsize;
			}
		}
	}
	
	return true;
}

bool DyscoAgentIn::insert_tag(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn*) {
	uint32_t tag = dc->get_dysco_tag(this->index);
	DyscoTcpOption* dopt = reinterpret_cast<DyscoTcpOption*>(pkt->append(DYSCO_TCP_OPTION_LEN));
	dopt->kind = DYSCO_TCP_OPTION;
	dopt->len = DYSCO_TCP_OPTION_LEN;
	dopt->padding = 0;
	dopt->tag = tag;

	tcp->offset += (DYSCO_TCP_OPTION_LEN << 2);
	ip->length = ip->length + be16_t(DYSCO_TCP_OPTION_LEN);
	
	return true;
}

bool DyscoAgentIn::rx_initiation_new(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;
	DyscoHashIn* cb_in = dc->insert_cb_in(this->index, ip, tcp, payload, payload_sz);
	if(!cb_in)
		return false;

	//debug
	fprintf(stderr, "IPHLEN, TCPHLEN, PAYLOAD_SZ: %lu %lu %u\n", ip_hlen, tcp_hlen, payload_sz);
	fprintf(stderr, "PAYLOAD: ");
	for(uint32_t i = 0; i < payload_sz; i++)
		fprintf(stderr, "%x ", payload[i]);
	fprintf(stderr, "\n\n");
		
	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	parse_tcp_syn_opt_r(tcp, cb_in);
	insert_tag(pkt, ip, tcp, cb_in);
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

	//debug
	fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());

	return true;
}

bool DyscoAgentIn::process_packet(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	//debug
	fprintf(stderr, "[%s]%s(IN): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp))
			return rx_initiation_new(pkt, ip, tcp);
		
		return false;
	}

	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			//L.796 -- dysco_input.c
		} else {
			//L.803 -- dysco_input.c
		}

		return false;
	}

	if(cb_in->two_paths) {
		//L.811 -- dysco_input.c
	}
	
	in_hdr_rewrite(ip, tcp, &cb_in->sup);
	
	/*fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());*/

	return true;
}

bool DyscoAgentIn::in_hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* sup) {
	if(!sup)
		return false;
	
	ip->src = be32_t(ntohl(sup->sip));
	ip->dst = be32_t(ntohl(sup->dip));
	tcp->src_port = be16_t(ntohs(sup->sport));
	tcp->dst_port = be16_t(ntohs(sup->dport));

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return sup;
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
	if(dc) {
		int cnt = batch->cnt();
		
		bess::Packet* pkt = 0;
		for(int i = 0; i < cnt; i++) {
			pkt = batch->pkts()[i];
			process_packet(pkt);
		}
	}
	
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
