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
	ns = arg.ns();

	return CommandSuccess();
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

	//debug
	/*fprintf(stderr, "[%s][DyscoAgentOut] receives %s:%u -> %s:%u\n",
		ns.c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());*/

	
	DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
	if(!cb_out) {
		cb_out = dc->lookup_output_pending(this->index, ip, tcp);
		if(cb_out) {
			//debug
			fprintf(stderr, "[%s][DyscoAgentOut] output_pending isn't NULL and calling handle_mb_out method\n", ns.c_str());
			return dc->handle_mb_out(this->index, pkt, ip, tcp, cb_out);
		}

		cb_out = dc->lookup_pending_tag(this->index, tcp);
		if(cb_out) {
			//debug
			fprintf(stderr, "[%s][DyscoAgentOut] output_pending_tag isn't NULL and calling handle_mb_out method\n", ns.c_str());
			update_five_tuple(ip, tcp, cb_out);
			return dc->handle_mb_out(this->index, pkt, ip, tcp, cb_out);
		}
	}

	if(isTCPSYN(tcp)) {
			//debug
		fprintf(stderr, "[%s][DyscoAgentOut] calling process_syn_out method\n", ns.c_str());
		cb_out = dc->process_syn_out(this->index, pkt, ip, tcp, cb_out);
		return cb_out ? true : false;
	}

	if(!cb_out)
		return false;

	if(cb_out->my_tp && isTCPACK(tcp))
		if(!cb_out->state_t)
			fix_rcv_window(cb_out);
	//L.1462 -- dysco_output.c ???

	translate_out(pkt, ip, tcp, cb_out);

	//debug
	/*fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n\n",
		ns.c_str(), name().c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());*/
		
	return true;
}

bool DyscoAgentOut::update_five_tuple(Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out)
		return false;
	
	cb_out->sup.sip = htonl(ip->src.value());
	cb_out->sup.dip = htonl(ip->dst.value());
	cb_out->sup.sport = htons(tcp->src_port.value());
	cb_out->sup.dport = htons(tcp->dst_port.value());
	
	return true;
}

DyscoHashOut* DyscoAgentOut::pick_path_seq(DyscoHashOut* cb_out, uint32_t seq) {
	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED)
			cb_out = cb_out->other_path;
	} else if(cb_out->use_np_seq) {
		cb_out = cb_out->other_path;
	} else if(!before(seq, cb_out->seq_cutoff))
		cb_out = cb_out->other_path;

	return cb_out;
}

DyscoHashOut* DyscoAgentOut::pick_path_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t ack = tcp->ack_num.value();

	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED)
			cb_out = cb_out->other_path;
	} else if(cb_out->valid_ack_cut) {
		if(cb_out->use_np_ack) {
			cb_out = cb_out->other_path;
		} else if(!after(cb_out->ack_cutoff, ack)) {
			if(tcp->flags & Tcp::kFin)
				cb_out = cb_out->other_path;
			else {
				tcp->ack_num = be32_t(cb_out->ack_cutoff);
				cb_out->ack_ctr++;
				if(cb_out->ack_ctr > 1)
					cb_out->use_np_ack = true;
			}
		}
	}

	return cb_out;
}

bool DyscoAgentOut::out_rewrite_seq(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->seq_delta) {
		uint32_t new_seq;
		uint32_t seq = tcp->seq_num.value();

		if(cb_out->seq_add)
			new_seq = seq + cb_out->seq_delta;
		else
			new_seq = seq - cb_out->seq_delta;

		tcp->seq_num = be32_t(new_seq);

		return true;
	}

	return false;
}

bool DyscoAgentOut::out_rewrite_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->ack_delta) {
		uint32_t new_ack;
		uint32_t ack = tcp->ack_num.value();

		if(cb_out->ack_add)
			new_ack = ack + cb_out->ack_delta;
		else
			new_ack = ack - cb_out->ack_delta;

		if(cb_out->sack_ok)
			tcp_sack(tcp, cb_out->ack_delta, cb_out->ack_add);
		
		tcp->ack_num = be32_t(new_ack);

		return true;
	}

	return false;
}

uint8_t* DyscoAgentOut::get_ts_option(Tcp* tcp) {
	uint8_t* ptr;
	uint32_t length;

	length = (tcp->offset * 4) - sizeof(Tcp);
	ptr = (uint8_t*)(tcp + 1);

	while(length > 0) {
		uint32_t opcode = *ptr++;
		uint32_t opsize;

		switch(opcode) {
		case TCPOPT_EOL:
			return 0;
			
		case TCPOPT_NOP:
			length--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;
			
			if(opsize > length)
				return 0;
			
			if(opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP)
				return ptr;
			
			ptr += opsize - 2;
			length -= opsize;			
		}
	}
	
	return 0;
}

bool DyscoAgentOut::out_rewrite_ts(Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoTcpTs* ts = (DyscoTcpTs*) get_ts_option(tcp);
	if(!ts)
		return false;

	uint32_t new_ts, new_tsr;
	
	if(cb_out->ts_delta) {
		if(cb_out->ts_add)
			new_ts = ntohl(ts->ts) + cb_out->ts_delta;
		else
			new_ts = ntohl(ts->ts) - cb_out->ts_delta;

		ts->ts = htonl(new_ts);
	}

	if(cb_out->tsr_delta) {
		if(cb_out->tsr_add)
			new_tsr = ntohl(ts->tsr) + cb_out->tsr_delta;
		else
			new_tsr = ntohl(ts->tsr) - cb_out->tsr_delta;

		ts->tsr = htonl(new_tsr);
	}
	
	return true;
}

bool DyscoAgentOut::out_rewrite_rcv_wnd(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->ws_delta) {
		uint16_t new_win;
		uint32_t wnd = tcp->window.value();

		wnd <<= cb_out->ws_in;
		wnd >>= cb_out->ws_out;
		tcp->window = be16_t(new_win);

		return true;
	}

	return false;
}

bool DyscoAgentOut::translate_out(bess::Packet*, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t seg_sz = ip->length.value() - ip_hlen - tcp_hlen;
	uint32_t seq = tcp->seq_num.value() + seg_sz;

	DyscoHashOut* other_path = cb_out->other_path;
	if(!other_path) {
		if(seg_sz > 0 && after(seq, cb_out->seq_cutoff))
			cb_out->seq_cutoff = seq;
	} else {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			if(seg_sz > 0)
				cb_out = pick_path_seq(cb_out, seq);
			else
				cb_out = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_SENT) {
			if(seg_sz > 0) {
				if(after(seq, cb_out->seq_cutoff))
					cb_out->seq_cutoff = seq;
			} else
				cb_out = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_RECEIVED) {
			if(seg_sz > 0) {
				cb_out = pick_path_seq(cb_out, seq);
				//if(!cb_out->old_path)

			} else
				cb_out = pick_path_ack(tcp, cb_out);
		}
	}

	out_rewrite_seq(tcp, cb_out);
	out_rewrite_ack(tcp, cb_out);

	if(cb_out->ts_ok)
		out_rewrite_ts(tcp, cb_out);

	if(cb_out->ws_ok)
		out_rewrite_rcv_wnd(tcp, cb_out);
	
	out_hdr_rewrite(ip, tcp, &cb_out->sub);
	
	return true;
}

bool DyscoAgentOut::out_hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* sub) {
	if(!sub)
		return false;

	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

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
