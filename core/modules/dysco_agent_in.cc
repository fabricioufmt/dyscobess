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

bool DyscoAgentIn::insert_tag(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn*) {
	uint32_t tag = dc->get_dysco_tag(this->index);
	DyscoTcpOption* dopt = reinterpret_cast<DyscoTcpOption*>(pkt->append(DYSCO_TCP_OPTION_LEN));
	dopt->kind = DYSCO_TCP_OPTION;
	dopt->len = DYSCO_TCP_OPTION_LEN;
	dopt->padding = 0;
	dopt->tag = tag;

	tcp->offset += (DYSCO_TCP_OPTION_LEN >> 2);
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
		
	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	dc->parse_tcp_syn_opt_r(tcp, cb_in);
	insert_tag(pkt, ip, tcp, cb_in);
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

	//debug
	fprintf(stderr, "[%s][DyscoAgentIn](end of rx_initiation_new): %s:%u -> %s:%u\n\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());

	return true;
}

bool DyscoAgentIn::remove_sc(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;

	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

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
	fprintf(stderr, "[%s][DyscoAgentIn] receives %s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
	
	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
			//debug
			fprintf(stderr, "[%s][DyscoAgentIn] new connection with payload\n", ns.c_str());
			return rx_initiation_new(pkt, ip, tcp);
		}
		
		return false;
	}

	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			//L.796 -- dysco_input.c
			dc->set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite2(ip, tcp, cb_in);
			
		} else {
			//It is retransmission packet, just remove sc (if there is) and insert Dysco Tag
			if(hasPayload(ip, tcp)) {
				remove_sc(pkt, ip, tcp);
				insert_tag(pkt, ip, tcp, cb_in);
				in_hdr_rewrite(ip, tcp, &cb_in->sup);
			}
		}

		return false;
	}

	if(cb_in->two_paths) {
		//L.811 -- dysco_input.c
	}
	
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

	//debug
	/*fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());*/

	return true;
}

bool DyscoAgentIn::in_rewrite_seq(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	if(cb_in->seq_delta) {
		uint32_t new_seq;
		uint32_t seq = tcp->seq_num.value();

		if(cb_in->seq_add)
			new_seq = seq + ntohl(cb_in->seq_delta);
		else
			new_seq = seq - ntohl(cb_in->seq_delta);

		tcp->seq_num = be32_t(new_seq);
	}

	return true;
}

bool DyscoAgentIn::tcp_sack(Tcp*, DyscoHashIn*) {
	//L.219 -- dysco_output.c
	return true;
}

bool DyscoAgentIn::in_rewrite_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	if(cb_in->ack_delta) {
		uint32_t new_ack;
		uint32_t ack = tcp->ack_num.value();

		if(cb_in->ack_add)
			new_ack = ack + ntohl(cb_in->ack_delta);
		else
			new_ack = ack - ntohl(cb_in->ack_delta);

		if(cb_in->sack_ok)
			tcp_sack(tcp, cb_in);
		
		tcp->ack_num = be32_t(new_ack);
	}

	return true;
}

DyscoTcpTs* DyscoAgentIn::get_ts_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP)
				return reinterpret_cast<DyscoTcpTs*>(ptr);

			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

bool DyscoAgentIn::in_rewrite_ts(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	DyscoTcpTs* ts = get_ts_option(tcp);
	if(!ts)
		return false;

	uint32_t new_ts, new_tsr;
	if(cb_in->ts_delta) {
		if(cb_in->ts_add)
			new_ts = ntohl(ts->ts) + ntohl(cb_in->ts_delta);
		else
			new_ts = ntohl(ts->ts) - ntohl(cb_in->ts_delta);

		new_ts = htonl(new_ts);
		ts->ts = new_ts;
		//Ronaldo
		//tcp_ts_rewrites++; L.406 -- dysco_input.c
	}

	if(cb_in->tsr_delta) {
		if(cb_in->tsr_add)
			new_tsr = ntohl(ts->tsr) + ntohl(cb_in->tsr_delta);
		else
			new_tsr = ntohl(ts->tsr) - ntohl(cb_in->tsr_delta);

		new_tsr = htonl(new_tsr);
		ts->tsr = new_tsr;
		//Ronaldo
		//tcp_ts_rewrites++; L.420 -- dysco_input.c
	}
		
	return true;
}

bool DyscoAgentIn::in_rewrite_rcv_wnd(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	if(cb_in->ws_delta) {
		uint16_t new_win;
		uint32_t wnd = tcp->window.value();

		wnd <<= ntohl(cb_in->ws_in);
		wnd >>= ntohl(cb_in->ws_out);
		new_win = htons(wnd);
		new_win = ntohs(new_win);
		tcp->window = be16_t(new_win);
	}

	return true;
}

bool DyscoAgentIn::in_hdr_rewrite2(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	DyscoTcpSession* sup = &cb_in->sup;
	
	ip->src = be32_t(ntohl(sup->sip));
	ip->dst = be32_t(ntohl(sup->dip));
	tcp->src_port = be16_t(ntohs(sup->sport));
	tcp->dst_port = be16_t(ntohs(sup->dport));

	in_rewrite_seq(tcp, cb_in);
	in_rewrite_ack(tcp, cb_in);
	if(cb_in->ts_ok)
		in_rewrite_ts(tcp, cb_in);
	if(cb_in->ws_ok)
		in_rewrite_rcv_wnd(tcp, cb_in);
	
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

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

	return true;
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
