#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"
#include "dysco_port_out.h"

//#define DEBUG 1

//debug
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

	netns_fd_ = 0;
	info_flag = false;
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
	
	/*inet_pton(AF_INET, arg.ip().c_str(), &devip);
	index = dc->get_index(arg.ns(), devip);
	ns = arg.ns();*/
	//if(!get_port_information())
	//	return CommandFailure(ENODEV, "DyscoVPort module is NULL.");
	
	return CommandSuccess();
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
	get_port_information();
		
	if(dc) {
		int cnt = batch->cnt();
		
		bess::Packet* pkt = 0;
		for(int i = 0; i < cnt; i++) {
			pkt = batch->pkts()[i];
			input(pkt);
		}
	}
	
	RunChooseModule(0, batch);
}

bool DyscoAgentIn::get_port_information() {
	if(info_flag)
		return true;
	
	gate_idx_t ogate_idx = 0; //always 1 output gate (DyscoVPortOut)

	if(!is_active_gate<bess::OGate>(ogates(), ogate_idx))
		return false;

	bess::OGate* ogate = ogates()[ogate_idx];
	if(!ogate)
		return false;

	Module* m_next = ogate->next();
	DyscoPortOut* dysco_port_out = reinterpret_cast<DyscoPortOut*>(m_next);
	if(!dysco_port_out)
		return false;
	
	DyscoVPort* dysco_vport = reinterpret_cast<DyscoVPort*>(dysco_port_out->port_);
	if(!dysco_vport)
		return false;

	info_flag = true;
	//memcpy(ns, dysco_vport->ns, sizeof(ns));
	ns = dysco_vport->ns;
	devip = dysco_vport->devip;
	netns_fd_ = dysco_vport->netns_fd_;
	index = dc->get_index(ns, devip);
	
	port = dysco_vport;
	
	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Some methods are just wrapper for DyscoCenter method.
*/

bool DyscoAgentIn::remove_sc(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;

	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	return true;
}

//L.82
//insert_pending method -- in DyscoCenter

//L.133
//insert_cb_in_reverse method -- in DyscoCenter

//L.191
//insert_cb_input method -- in DyscoCenter

//L.258
//lookup_input method -- in DyscoCenter

//Ronaldo: Simple Checksum computation?
//L.282
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

//L.327
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

//L.355
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

		//TODO
		//if(cb_in->sack_ok)
		//	dc->tcp_sack(tcp, cb_in);
		
		tcp->ack_num = be32_t(new_ack);
	}

	return true;
}

//L.384
bool DyscoAgentIn::in_rewrite_ts(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	DyscoTcpTs* ts = dc->get_ts_option(tcp);
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
		//Ronaldo: is it just statistic?
		//tcp_ts_rewrites++; L.406 -- dysco_input.c
	}

	if(cb_in->tsr_delta) {
		if(cb_in->tsr_add)
			new_tsr = ntohl(ts->tsr) + ntohl(cb_in->tsr_delta);
		else
			new_tsr = ntohl(ts->tsr) - ntohl(cb_in->tsr_delta);

		new_tsr = htonl(new_tsr);
		ts->tsr = new_tsr;
		//Ronaldo: is it just statistic?
		//tcp_ts_rewrites++; L.420 -- dysco_input.c
	}
		
	return true;
}

//L.432
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

//Ronaldo: about csum functions, is really necessary?
//L.458
bool DyscoAgentIn::in_hdr_rewrite_csum(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
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

//L.505
bool DyscoAgentIn::rx_initiation_new(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;

	if(payload_sz) {
		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		DyscoHashIn* cb_in = dc->insert_cb_input(this->index, ip, tcp, payload, payload_sz);
		if(!cb_in)
			return false;
		
		remove_sc(pkt, ip, tcp);
		dc->parse_tcp_syn_opt_r(tcp, cb_in);
		dc->insert_tag(this->index, pkt, ip, tcp);
		in_hdr_rewrite(ip, tcp, &cb_in->sup);
	}
	
#ifdef DEBUG
	fprintf(stderr, "[%s][DyscoAgentIn](end of rx_initiation_new): %s:%u -> %s:%u\n\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
#endif
	return true;
}

//L.545
bool DyscoAgentIn::set_ack_number_out(uint32_t i, Tcp* tcp, DyscoHashIn* cb_in) {
	return dc->set_ack_number_out(i, tcp, cb_in);
}

//L.601
/*
bool DyscoAgentIn::set_zero_window(Tcp* tcp) {
	tcp->window = be16_t(0);
}
*/

//L.614
bool DyscoAgentIn::in_two_paths_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out)
		return false;

	if(cb_out->old_path) {
		if(cb_out->state_t) {
			if(cb_out->state == DYSCO_ESTABLISHED)
				cb_in->two_paths = false;
		} else {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = true;
				cb_in->two_paths = false;
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out)
			return false;

		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED)
			cb_in->two_paths = false;
		else {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = true;
				cb_in->two_paths = false;
			}
		}
	}

	return true;
}

//L.683
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out)
		return false;

	if(!cb_out->old_path) {
		DyscoHashOut* old_out = cb_out->other_path;

		if(!old_out)
			return false;

		if(old_out->state == DYSCO_SYN_SENT || old_out->state == DYSCO_SYN_RECEIVED) {
			uint32_t seq = tcp->seq_num.value();
			uint32_t delta;

			if(cb_out->in_iack < cb_out->out_iack) {
				delta = cb_out->out_iack - cb_out->in_iack;
				seq -= delta;
			} else {
				delta = cb_out->in_iack - cb_out->out_iack;
				seq += delta;
			}

			if(old_out->valid_ack_cut) {
				if(dc->before(seq, old_out->ack_cutoff))
					old_out->ack_cutoff = seq;
			} else {
				old_out->ack_cutoff = seq;
				old_out->valid_ack_cut = 1;
			}
		}
	}

	return true;
}

//L.753
bool DyscoAgentIn::input(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

#ifdef DEBUG
	fprintf(stderr, "[%s][DyscoAgentIn] receives %s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
#endif
	//TODO
	if(isReconfigPacket(ip, tcp))
		return control_input(ip);
	
	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] new connection with payload\n", ns.c_str());
#endif
			return rx_initiation_new(pkt, ip, tcp);
		}
		
		return false;
	}

	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);
			
		} else {
			//It is retransmission packet, just remove sc (if there is) and insert Dysco Tag
			if(hasPayload(ip, tcp)) {
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn] it's retransmission of TCP SYN w payload\n", ns.c_str());
#endif
				remove_sc(pkt, ip, tcp);
				dc->insert_tag(this->index, pkt, ip, tcp);
				in_hdr_rewrite(ip, tcp, &cb_in->sup);
			}
		}

		return false;
	}

	if(cb_in->two_paths) {
		if(hasPayload(ip, tcp)) {
			if(!in_two_paths_data_seg(tcp, cb_in))
				return false;
		} else
			in_two_paths_ack(tcp, cb_in);
	}
	
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

#ifdef DEBUG
	fprintf(stderr, "[%s][DyscoAgentIn](OUT): %s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());
#endif
	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control input
*/

DyscoCbReconfig* DyscoAgentIn::insert_rcb_control_input(Ipv4* ip, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->super;
	rcb->leftSS = cmsg->leftSS;
	rcb->rightSS = cmsg->rightSS;
	rcb->sub_in.sip = ip->src.value();
	rcb->sub_in.dip = ip->dst.value();
	rcb->sub_in.sport = cmsg->sport;
	rcb->sub_in.dport = cmsg->dport;
	rcb->sub_out.sip = 0;

	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);

	rcb->leftIts = ntohl(cmsg->leftIts);
	rcb->leftItsr = ntohl(cmsg->leftItsr);

	rcb->leftIws = ntohl(cmsg->leftIws);
	rcb->leftIwsr = ntohl(cmsg->leftIwsr);

	rcb->sack_ok = ntohs(cmsg->sackOk);

	if(!dc->insert_hash_reconfig(this->index, rcb))
		return 0;
	
	return rcb;
}

DyscoHashOut* DyscoAgentIn::build_cb_in_reverse(Ipv4* ip, DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();

	cb_out->sup.sip = rcb->super.dip;
	cb_out->sup.dip = rcb->super.sip;
	cb_out->sup.sport = rcb->super.dport;
	cb_out->sup.dport = rcb->super.sport;

	cb_out->sub.sip = ip->dst.value();
	cb_out->sub.dip = ip->src.value();
	cb_out->sub.sport = rcb->sub_in.dport;
	cb_out->sub.dport = rcb->sub_in.sport;

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIack;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIseq;

	return cb_out;
}

bool DyscoAgentIn::compute_deltas_in(DyscoHashIn* cb_in, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	cb_in->out_iseq = old_out->in_iack;
	cb_in->out_iack = old_out->in_iseq;

	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
		cb_in->seq_add = true;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
		cb_in->seq_add = false;
	}

	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
		cb_in->ack_add = true;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
		cb_in->ack_add = false;
	}

	if(rcb->leftIts) {
		cb_in->ts_ok = 1;
		cb_in->ts_in = rcb->leftIts;
		cb_in->ts_out = old_out->dcb_in->ts_out;

		if(cb_in->ts_in < cb_in->ts_out) {
			cb_in->ts_delta = cb_in->ts_out - cb_in->ts_in;
			cb_in->ts_add = true;
		} else {
			cb_in->ts_delta = cb_in->ts_in - cb_in->ts_out;
			cb_in->ts_add = false;
		}

		cb_in->tsr_in = rcb->leftItsr;
		cb_in->tsr_out = old_out->dcb_in->tsr_out;

		if(cb_in->tsr_in < cb_in->tsr_out) {
			cb_in->tsr_delta = cb_in->tsr_out - cb_in->tsr_in;
			cb_in->tsr_add = true;
		} else {
			cb_in->tsr_delta = cb_in->tsr_in - cb_in->tsr_out;
			cb_in->tsr_add = false;
		}
	} else
		cb_in->ts_ok = 0;

	if(rcb->leftIws) {
		cb_in->ws_ok = 1;
		cb_in->ws_in = rcb->leftIws;
		cb_in->ws_out = old_out->ws_in;

		if(cb_in->ws_in < cb_in->ws_out)
			cb_in->ws_delta = cb_in->ws_out - cb_in->ws_in;
		else
			cb_in->ws_delta = cb_in->ws_in - cb_in->ws_out;
	} else
		cb_in->ws_ok = 0;

	cb_in->sack_ok = rcb->sack_ok;

	return true;
}

bool DyscoAgentIn::compute_deltas_out(DyscoHashOut* cb_out, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	cb_out->in_iseq = old_out->in_iseq;
	cb_out->in_iack = old_out->in_iack;

	if(cb_out->in_iseq < cb_out->out_iseq) {
		cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
		cb_out->seq_add = true;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
		cb_out->seq_add = false;
	}

	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
		cb_out->ack_add = true;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
		cb_out->ack_add = false;
	}

	if(rcb->leftIts) {
		cb_out->ts_ok = 1;
		cb_out->ts_in = old_out->ts_in;
		cb_out->ts_out = rcb->leftItsr;

		if(cb_out->ts_in < cb_out->ts_out) {
			cb_out->ts_delta = cb_out->ts_out - cb_out->ts_in;
			cb_out->ts_add = true;
		} else {
			cb_out->ts_delta = cb_out->ts_in - cb_out->ts_out;
			cb_out->ts_add = false;
		}

		cb_out->tsr_in = old_out->tsr_in;
		cb_out->tsr_out = rcb->leftIts;

		if(cb_out->tsr_in < cb_out->tsr_out) {
			cb_out->tsr_delta = cb_out->tsr_out - cb_out->tsr_in;
			cb_out->tsr_add = true;
		} else {
			cb_out->tsr_delta = cb_out->tsr_in - cb_out->tsr_out;
			cb_out->tsr_add = false;
		}
	}

	if(rcb->leftIwsr) {
		cb_out->ws_ok = 1;
		cb_out->ws_in = old_out->ws_in;
		cb_out->ws_out = rcb->leftIwsr;

		if(cb_out->ws_in < cb_out->ws_out)
			cb_out->ws_delta = cb_out->ws_out - cb_out->ws_in;
		else
			cb_out->ws_delta = cb_out->ws_in - cb_out->ws_out;
	} else
		cb_out->ws_ok = 0;

	cb_out->sack_ok = rcb->sack_ok;

	return true;
}

bool DyscoAgentIn::control_config_rightA(DyscoCbReconfig* rcb, DyscoControlMessage* cmsg, DyscoHashIn* cb_in, DyscoHashOut* cb_out) {
	DyscoTcpSession local_ss;

	local_ss.sip = cmsg->rightSS.dip;
	local_ss.dip = cmsg->rightSS.sip;
	local_ss.sport = cmsg->rightSS.dport;
	local_ss.dport = cmsg->rightSS.sport;

	DyscoHashOut* old_out = dc->lookup_output_by_ss(this->index, &local_ss);

	if(!old_out) {
		delete cb_in;
		dc->remove_reconfig(this->index, rcb);

		return false;
	}

	cb_in->sup = cmsg->rightSS;
	compute_deltas_in(cb_in, old_out, rcb);
	compute_deltas_out(cb_out, old_out, rcb);
	cb_in->two_paths = true;

	rcb->old_dcb = old_out;
	rcb->new_dcb = cb_out;

	cb_out->other_path = old_out;

	if(ntohs(cmsg->semantic) == STATE_TRANSFER)
		old_out->state_t = true;

	return true;
}

bool DyscoAgentIn::control_reconfig_in(Ipv4* ip, DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashIn* cb_in = new DyscoHashIn();

	cb_in->sub = rcb->sub_in;
	cb_in->in_iseq = rcb->leftIseq;
	cb_in->in_iack = rcb->leftIack;
	cb_in->two_paths = false;

	DyscoHashOut* cb_out = build_cb_in_reverse(ip, rcb);
	if(!cb_out) {
		delete cb_in;
		dc->remove_reconfig(this->index, rcb);

		return false;
	}

	cb_out->dcb_in = cb_in;
	cb_in->dcb_out = cb_out;

	//verify htonl
	if(ip->dst.value() == cmsg->rightA) {
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out))
			return 0;
	} else {
		cb_in->sup = rcb->super;
		cb_in->out_iseq = rcb->leftIseq;
		cb_in->out_iack = rcb->leftIack;
		cb_in->seq_delta = cb_in->ack_delta = 0;

		if(rcb->leftIts) {
			cb_in->ts_in = cb_in->ts_out = rcb->leftIts;
			cb_in->ts_delta = 0;
			cb_in->ts_ok = 1;
		} else
			cb_in->ts_ok = 0;

		if(rcb->leftIws) {
			cb_in->ws_in = cb_in->ws_out = rcb->leftIws;
			cb_in->ws_delta = 0;
			cb_in->ws_ok = 1;
		} else
			cb_in->ws_ok = 0;

		cb_out->sack_ok = cb_in->sack_ok = rcb->sack_ok;
		dc->insert_hash_output(this->index, cb_out);
	}

	dc->insert_hash_input(this->index, cb_in);

	return true;
}

// or UDP* udp?
bool DyscoAgentIn::control_input(Ipv4* ip) {

	DyscoControlMessage* cmsg;
	DyscoCbReconfig* rcb;

	/*
	  TODO: cmsg will be filled by packet payload
	 */
	cmsg = 0;// TODO: test
	
	switch(cmsg->mtype) {
	case DYSCO_SYN:
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(rcb)
			return true;

		rcb = insert_rcb_control_input(ip, cmsg);;
		if(!rcb)
			return false;

		return control_reconfig_in(ip, rcb, cmsg);

	case DYSCO_SYN_ACK:
		//verify htonl
		if(ip->dst.value() == cmsg->leftA) {
			DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);

			if(!cb_out)
				return true;

			if(cb_out->state == DYSCO_ESTABLISHED) {
				// It is a retransmission
				break;
			}

			cb_out->ack_cutoff = ntohl(cmsg->seqCutoff);
			cb_out->valid_ack_cut = true;
		}
		break;

	case DYSCO_ACK:
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(!rcb)
			break;

		//verify htonl
		if(cmsg->rightA == ip->dst.value()) {
			DyscoHashOut* old_out;
			DyscoHashOut* new_out;
			uint32_t old_out_ack_cutoff;

			if(!rcb->old_dcb)
				break;

			old_out = rcb->old_dcb;

			if(!old_out->other_path)
				break;

			new_out = old_out->other_path;
			old_out_ack_cutoff = ntohl(cmsg->seqCutoff);
			if(new_out->in_iack < new_out->out_iack) {
				uint32_t delta = new_out->out_iack - new_out->in_iack;
				old_out_ack_cutoff += delta;
			}

			if(old_out->state == DYSCO_ESTABLISHED)
				return true;

			if(!old_out->state_t) {
				old_out->ack_cutoff = old_out_ack_cutoff;
				old_out->valid_ack_cut = true;
				old_out->state = DYSCO_ESTABLISHED;
			}
		}
	case DYSCO_FIN:
		break;

	case DYSCO_STATE_TRANSFERRED:
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(!rcb)
			return true;

		// verify htonl
		if(ip->dst.value() == cmsg->leftA) {
			dc->replace_cb_leftA(rcb, cmsg);
		} else if(ip->dst.value() == cmsg->rightA) {
			DyscoHashOut* cb_out = rcb->old_dcb;
			cb_out->state = DYSCO_ESTABLISHED;
		}

		break;
	}

	//skb modifies???

	return true;
}



ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
