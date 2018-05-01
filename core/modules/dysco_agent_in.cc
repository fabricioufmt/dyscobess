#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"
#include "dysco_port_out.h"

//#define DEBUG 1
#define DEBUG_RECONFIG 1

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

char* print_ss1(DyscoTcpSession ss) {
	char* buf = (char*) malloc(1024);
	sprintf(buf, "%s:%u -> %s:%u",
		printip1(ntohl(ss.sip)), ntohs(ss.sport),
		printip1(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}

const Commands DyscoAgentIn::cmds = {
	{"get_info", "EmptyArg", MODULE_CMD_FUNC(&DyscoAgentIn::CommandInfo), Command::THREAD_UNSAFE}
};
	
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
	
	return CommandSuccess();
}

CommandResponse DyscoAgentIn::CommandInfo(const bess::pb::EmptyArg&) {
	if(get_port_information())
		return CommandSuccess();
	
	return CommandFailure(EINVAL, "ERROR: Port information.");
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
	if(!dc) {
		RunChooseModule(0, batch);
		return;
	}
	
	bess::PacketBatch out_gates[2];
	out_gates[0].clear();
	out_gates[1].clear();

	Ethernet* eth;
	bess::Packet* pkt;
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();

		if(!isIP(eth)) {
			out_gates[0].add(pkt);
			continue;
		}

		Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
		size_t ip_hlen = ip->header_length << 2;
		if(!isTCP(ip)) {
			out_gates[0].add(pkt);
			continue;
		}

		Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentIn] receives %s:%u -> %s:%u [%X:%X]\n",
			ns.c_str(),
			printip1(ip->src.value()), tcp->src_port.value(),
			printip1(ip->dst.value()), tcp->dst_port.value(),
			tcp->seq_num.value(), tcp->ack_num.value());
#endif

		if(!isReconfigPacket(ip, tcp)) {
			input(pkt, ip, tcp);
			out_gates[0].add(pkt);
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s:%u -> %s:%u [%X:%X]\n\n",
				ns.c_str(),
				printip1(ip->src.value()), tcp->src_port.value(),
				printip1(ip->dst.value()), tcp->dst_port.value(),
				tcp->seq_num.value(), tcp->ack_num.value());
#endif
		} else {
			switch(control_input(pkt, ip, tcp)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
				break;
			case TO_GATE_1:
				out_gates[1].add(pkt);
				break;
			case END:
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control]: 3-way from Reconfiguration Session is DONE.\n\n", ns.c_str());
#endif
				break;
			default:
				break;
			}

#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n",
				ns.c_str(),
				printip1(ip->src.value()), tcp->src_port.value(),
				printip1(ip->dst.value()), tcp->dst_port.value(),
				tcp->seq_num.value(), tcp->ack_num.value());
#endif
		}
	}
	
	batch->clear();
	RunChooseModule(0, &(out_gates[0]));
	RunChooseModule(1, &(out_gates[1]));
}

bool DyscoAgentIn::get_port_information() {
	gate_idx_t ogate_idx = 0;

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
	if(!cb_in) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in is NULL\n", ns.c_str());
#endif		
		return false;
	}
	
	if(cb_in->seq_delta) {
		uint32_t new_seq;
		uint32_t seq = tcp->seq_num.value();

		if(cb_in->seq_add)
			new_seq = seq + cb_in->seq_delta;
		else
			new_seq = seq - cb_in->seq_delta;

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] old seq: %X, new seq: %X, seq_delta: %X.\n", ns.c_str(), seq, new_seq, cb_in->seq_delta);
#endif
		
		tcp->seq_num = be32_t(new_seq);
		
		return true;
	}

	return false;
}

//L.355
bool DyscoAgentIn::in_rewrite_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in) {
		return false;
	}

	if(cb_in->ack_delta) {
		uint32_t new_ack;
		uint32_t ack = tcp->ack_num.value();

		if(cb_in->ack_add)
			new_ack = ack + cb_in->ack_delta;
		else
			new_ack = ack - cb_in->ack_delta;

		//TODO
		//if(cb_in->sack_ok)
		//	dc->tcp_sack(tcp, cb_in);

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] old ack: %X, new ack: %X, ack_delta: %X.\n", ns.c_str(), ack, new_ack, cb_in->ack_delta);
#endif
		
		tcp->ack_num = be32_t(new_ack);

		return true;
	}
	
	return false;
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
			new_ts = ntohl(ts->ts) + cb_in->ts_delta;
		else
			new_ts = ntohl(ts->ts) - cb_in->ts_delta;

		new_ts = htonl(new_ts);
		ts->ts = new_ts;
		//Ronaldo: is it just statistic?
		//tcp_ts_rewrites++; L.406 -- dysco_input.c
	}

	if(cb_in->tsr_delta) {
		if(cb_in->tsr_add)
			new_tsr = ntohl(ts->tsr) + cb_in->tsr_delta;
		else
			new_tsr = ntohl(ts->tsr) - cb_in->tsr_delta;

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

		wnd <<= cb_in->ws_in;
		wnd >>= cb_in->ws_out;
		new_win = htons(wnd);
		new_win = ntohs(new_win);
		tcp->window = be16_t(new_win);
	}

	return true;
}

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

		cb_in->lastSeq_ho = tcp->seq_num.value();
		cb_in->lastAck_ho = tcp->ack_num.value();
		
		remove_sc(pkt, ip, tcp);
		dc->parse_tcp_syn_opt_r(tcp, cb_in);
		dc->insert_tag(this->index, pkt, ip, tcp);
		in_hdr_rewrite(ip, tcp, &cb_in->sup);
	}
	
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
				cb_in->two_paths = 0;
		} else {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out)
			return false;

		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED)
			cb_in->two_paths = 0;
		else {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
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
bool DyscoAgentIn::input(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] receives a TCP SYN+PAYLOAD segment\n", ns.c_str());
#endif
			bool retvalue = rx_initiation_new(pkt, ip, tcp);

			return retvalue;
		}
		
		return false;
	}

	//TEST
	cb_in->lastSeq_ho = tcp->seq_num.value();
	cb_in->lastAck_ho = tcp->ack_num.value();
	
	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);
		} else {
			//It is retransmission packet, just remove sc (if there is) and insert Dysco Tag
			if(hasPayload(ip, tcp)) {
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn] receives a TCP SYN+PAYLOAD retransmission segment.\n", ns.c_str());
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
	
	in_hdr_rewrite_csum(ip, tcp, cb_in);

	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control input
*/

DyscoCbReconfig* DyscoAgentIn::insert_rcb_control_input(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->super;
	rcb->leftSS = cmsg->leftSS;
	rcb->rightSS = cmsg->rightSS;
	rcb->sub_in.sip = htonl(ip->src.value());
	rcb->sub_in.dip = htonl(ip->dst.value());
	rcb->sub_in.sport = htons(tcp->src_port.value());
	rcb->sub_in.dport = htons(tcp->dst_port.value());
	//rcb->sub_in.sport = cmsg->sport;
	//rcb->sub_in.dport = cmsg->dport;
	rcb->sub_out.sip = 0;

	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cmsg->leftIseq = %X\n",
		ns.c_str(), ntohl(cmsg->leftIseq));
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cmsg->leftIack = %X\n",
		ns.c_str(), ntohl(cmsg->leftIack));
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cmsg->seqCutoff = %X\n",
		ns.c_str(), ntohl(cmsg->seqCutoff));
#endif
	
	rcb->leftIts = ntohl(cmsg->leftIts);
	rcb->leftItsr = ntohl(cmsg->leftItsr);

	rcb->leftIws = ntohl(cmsg->leftIws);
	rcb->leftIwsr = ntohl(cmsg->leftIwsr);

	rcb->sack_ok = ntohl(cmsg->sackOk);
	
	if(!dc->insert_hash_reconfig(this->index, rcb)) {
		delete rcb;
		return 0;
	}
	
	return rcb;
}

DyscoHashOut* DyscoAgentIn::build_cb_in_reverse(Ipv4* ip, DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();

	cb_out->sup.sip = rcb->super.dip;
	cb_out->sup.dip = rcb->super.sip;
	cb_out->sup.sport = rcb->super.dport;
	cb_out->sup.dport = rcb->super.sport;

	cb_out->sub.sip = htonl(ip->dst.value());
	cb_out->sub.dip = htonl(ip->src.value());
	cb_out->sub.sport = rcb->sub_in.dport;
	cb_out->sub.dport = rcb->sub_in.sport;

	//TEST
	//cb_out->out_iseq = cb_out->in_iseq = rcb->leftIack;
	//cb_out->out_iack = cb_out->in_iack = rcb->leftIseq;

	return cb_out;
}

bool DyscoAgentIn::compute_deltas_in(DyscoHashIn* cb_in, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	//TEST
	//cb_in->in_iseq++;
	//cb_in->out_iseq = old_out->in_iack;
	//cb_in->out_iack = old_out->in_iseq;
	/*
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] compute_deltas_in.\n", ns.c_str());
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->in_iseq: %X (should be zero, when ACK received is filled.\n", ns.c_str(), cb_in->in_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->in_iack: %X.\n", ns.c_str(), cb_in->in_iack);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->out_iseq: %X.\n", ns.c_str(), cb_in->out_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->out_iack: %X.\n", ns.c_str(), cb_in->out_iack);	
#endif
	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta1 = %X (%X - %X).\n", ns.c_str(), cb_in->seq_delta, cb_in->out_iseq, cb_in->in_iseq);
#endif
		cb_in->seq_add = 1;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta2 = %X (%X - %X).\n", ns.c_str(), cb_in->seq_delta, cb_in->in_iseq, cb_in->out_iseq);
#endif
		cb_in->seq_add = 0;
	}
	
	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta1 = %X (%X - %X).\n", ns.c_str(), cb_in->ack_delta, cb_in->out_iack, cb_in->in_iack);
#endif
		cb_in->ack_add = 1;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta2 = %X (%X - %X).\n", ns.c_str(), cb_in->ack_delta, cb_in->in_iack, cb_in->out_iack);
#endif
		cb_in->ack_add = 0;
	}
*/
	if(rcb->leftIts) {
		cb_in->ts_ok = 1;
		cb_in->ts_in = rcb->leftIts;
		cb_in->ts_out = old_out->dcb_in->ts_out;

		if(cb_in->ts_in < cb_in->ts_out) {
			cb_in->ts_delta = cb_in->ts_out - cb_in->ts_in;
			cb_in->ts_add = 1;
		} else {
			cb_in->ts_delta = cb_in->ts_in - cb_in->ts_out;
			cb_in->ts_add = 0;
		}

		cb_in->tsr_in = rcb->leftItsr;
		cb_in->tsr_out = old_out->dcb_in->tsr_out;

		if(cb_in->tsr_in < cb_in->tsr_out) {
			cb_in->tsr_delta = cb_in->tsr_out - cb_in->tsr_in;
			cb_in->tsr_add = 1;
		} else {
			cb_in->tsr_delta = cb_in->tsr_in - cb_in->tsr_out;
			cb_in->tsr_add = 0;
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
	//TEST
	//old_out->in_iseq = cb_out->in_iseq;
	//old_out->out_iseq = cb_out->in_iseq;
	//cb_out->in_iseq = old_out->in_iseq;
	//cb_out->in_iack = old_out->in_iack;
	/*
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] compute_deltas_out.\n", ns.c_str());
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->in_iseq: %X.\n", ns.c_str(), cb_out->in_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->in_iack: %X.\n", ns.c_str(), cb_out->in_iack);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->out_iseq: %X.\n", ns.c_str(), cb_out->out_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->out_iack: %X.\n", ns.c_str(), cb_out->out_iack);
#endif
	
	if(cb_out->in_iseq < cb_out->out_iseq) {
		cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->seq_delta1 = %u (%X - %X).\n", ns.c_str(), cb_out->seq_delta, cb_out->out_iseq, cb_out->in_iseq);
#endif
		cb_out->seq_add = 1;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->seq_delta2 = %u (%X - %X).\n", ns.c_str(), cb_out->seq_delta, cb_out->in_iseq, cb_out->out_iseq);
#endif
		cb_out->seq_add = 0;
	}

	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
		cb_out->ack_add = 0;
	}
	*/
	if(rcb->leftIts) {
		cb_out->ts_ok = 1;
		cb_out->ts_in = old_out->ts_in;
		cb_out->ts_out = rcb->leftItsr;

		if(cb_out->ts_in < cb_out->ts_out) {
			cb_out->ts_delta = cb_out->ts_out - cb_out->ts_in;
			cb_out->ts_add = 1;
		} else {
			cb_out->ts_delta = cb_out->ts_in - cb_out->ts_out;
			cb_out->ts_add = 0;
		}

		cb_out->tsr_in = old_out->tsr_in;
		cb_out->tsr_out = rcb->leftIts;

		if(cb_out->tsr_in < cb_out->tsr_out) {
			cb_out->tsr_delta = cb_out->tsr_out - cb_out->tsr_in;
			cb_out->tsr_add = 1;
		} else {
			cb_out->tsr_delta = cb_out->tsr_in - cb_out->tsr_out;
			cb_out->tsr_add = 0;
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

	/*
	local_ss.sip = cmsg->rightSS.dip;
	local_ss.dip = cmsg->rightSS.sip;
	local_ss.sport = cmsg->rightSS.dport;
	local_ss.dport = cmsg->rightSS.sport;
	*/
	//TEST
	local_ss.sip = cmsg->super.dip;
	local_ss.dip = cmsg->super.sip;
	local_ss.sport = cmsg->super.dport;
	local_ss.dport = cmsg->super.sport;
	
	DyscoHashOut* old_out = dc->lookup_output_by_ss(this->index, &local_ss);
	
	if(!old_out) {
		delete cb_in;
		dc->remove_reconfig(this->index, rcb);
		//TEST
		delete rcb;

		return false;
	}

	//Test
	//cb_in->sup = cmsg->rightSS;
	compute_deltas_in(cb_in, old_out, rcb);
	compute_deltas_out(cb_out, old_out, rcb);

	cb_in->two_paths = 1;
	cb_in->sup = cmsg->super;

	rcb->new_dcb = cb_out;
	rcb->old_dcb = old_out;
	cb_out->other_path = old_out;
	
	if(cmsg->semantic == STATE_TRANSFER)
		old_out->state_t = 1;
	
	return true;
}

CONTROL_RETURN DyscoAgentIn::control_reconfig_in(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, uint8_t*, DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] control_reconfig_in method\n", ns.c_str());
	fprintf(stderr, "[%s][DyscoAgentIn-Control] created rcb(super: %s)\n", ns.c_str(), print_ss1(rcb->super));
	fprintf(stderr, "[%s][DyscoAgentIn-Control] rcb->leftIseq: %X and rcb->leftIack: %X\n", ns.c_str(), rcb->leftIseq, rcb->leftIack);
#endif
	
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;
	if(!isRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG		
		fprintf(stderr, "[%s][DyscoAgentIn-Control] It isn't the right anchor\n", ns.c_str());
#endif
		size_t tcp_hlen = tcp->offset << 2;
		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;

		uint32_t payload_sz = ip->length.value() - (ip->header_length << 2) - tcp_hlen;

		cb_in = dc->insert_cb_input(this->index, ip, tcp, payload, payload_sz);
		if(!cb_in)
			return ERROR;
		
		cb_in->in_iseq = rcb->leftIseq;
		cb_in->in_iack = rcb->leftIack;
		cb_in->two_paths = 0;
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] It's the right anchor.\n", ns.c_str());
#endif	
		cb_in = new DyscoHashIn();
		cb_in->sub = rcb->sub_in;

		//TEST
		//cb_in->in_iseq = tcp->seq_num.value();
		//cb_in->in_iack = tcp->ack_num.value();
		cb_in->out_iseq = rcb->leftIseq;
		cb_in->out_iack = rcb->leftIack;
				
		cb_in->is_reconfiguration = 1;
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
		cb_out = build_cb_in_reverse(ip, rcb);
		if(!cb_out) {
			delete cb_in;
			dc->remove_reconfig(this->index, rcb);
			//TEST
			delete rcb;
			
			return ERROR;
		}

		//TEST //TODO //Ronaldo
		create_synack(pkt, ip, tcp);
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] creating SYN/ACK segment.\n", ns.c_str());
#endif
		//TEST
		cb_out->ack_cutoff = ntohl(cmsg->seqCutoff);
		cb_out->in_iseq = rcb->leftIack;
		cb_out->in_iack = rcb->leftIseq;
		cb_out->out_iseq = tcp->seq_num.value(); //new values due create_synack method (already switched)
		cb_out->out_iack = tcp->ack_num.value(); //new values due create_synack method
		cb_in->in_iack = cb_out->out_iack;
		
		cb_out->is_reconfiguration = 1;
		cb_out->dcb_in = cb_in;
		cb_in->dcb_out = cb_out;
		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out))
			return ERROR;
		
		//replace_cb_rightA method from control_output
		DyscoHashOut* old_out = rcb->old_dcb;
		DyscoHashOut* new_out = rcb->new_dcb;
		uint32_t seq_cutoff = old_out->seq_cutoff;




		
		
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] old_out->lastSeq_ho = %X.\n", ns.c_str(), old_out->lastSeq_ho);
		fprintf(stderr, "[%s][DyscoAgentIn-Control] old_out->seq_cutoff = %X.\n", ns.c_str(), old_out->seq_cutoff);
		fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->seq_cutoff = %X.\n", ns.c_str(), new_out->seq_cutoff);
		fprintf(stderr, "[%s][DyscoAgentIn-Control] cmsg->seqCutoff = %X.\n", ns.c_str(), ntohl(cmsg->seqCutoff));
#endif
		
		old_out->old_path = 1;
		old_out->state = DYSCO_SYN_RECEIVED;
		old_out->other_path = new_out;

		if(new_out->seq_add)
			seq_cutoff += new_out->seq_delta;
		else
			seq_cutoff -= new_out->seq_delta;

		//Not necessary
		cmsg->seqCutoff = htonl(seq_cutoff);

		//TEST
		//cb_in->in_iseq = rcb->leftIseq;
		//cb_in->in_iack = rcb->leftIack;
		cb_in->two_paths = 0;

		if(!dc->insert_hash_input(this->index, cb_in)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] insert_hash_input returns false.\n", ns.c_str());
#endif
			//TEST
			delete cb_in;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] insert_hash_input returns true.\n", ns.c_str());
#endif	       
		}

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] TO_GATE_1.\n", ns.c_str());
#endif	       
		
		return TO_GATE_1;
	}

	
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] Do nothing, follows regular algorithm and forwads it to host.\n",
		ns.c_str());
#endif
	//cb_in->sup = rcb->super;
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

	cb_in->dcb_out->sack_ok = cb_in->sack_ok = rcb->sack_ok;

	dc->insert_hash_output(this->index, cb_in->dcb_out);

	//TODO: should remove payload and forwards to app
	//RECONFIG
	
	cb_in->is_reconfiguration = 1;
	cb_in->dcb_out->is_reconfiguration = 1;
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control]: setting cb_in and cb_out as reconfiguration\n", ns.c_str());
#endif
	memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
	remove_sc(pkt, ip, tcp);
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] Removes payload, translates session and forwards to GATE 0 (Host).\n", ns.c_str());
#endif
	
	return TO_GATE_0;
}

CONTROL_RETURN DyscoAgentIn::control_input(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	DyscoHashIn* cb_in;
	DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg = 0;
	size_t tcp_hlen = tcp->offset << 2;
	
	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] DYSCO_SYN message.\n", ns.c_str());
#endif

		//Impossible case
		//if(!hasPayload(ip, tcp))
		//	return END;

		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
		
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(rcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] It's a retransmission of reconfiguration packet.\n", ns.c_str());
#endif
			//TODO: verify, when is left or right anchor, should do nothing
			//when not, should remove_payload and forward to gate0
			return IS_RETRANSMISSION;
		}

		rcb = insert_rcb_control_input(ip, tcp, cmsg);
			
		if(!rcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] Error to insert rcb control input.\n", ns.c_str());
#endif			
			return ERROR;
		}

		return control_reconfig_in(pkt, ip, tcp, payload, rcb, cmsg);
		
	} else if(isTCPSYN(tcp) && isTCPACK(tcp)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] DYSCO_SYN_ACK message.\n", ns.c_str());
#endif

		cb_in = dc->lookup_input(this->index, ip, tcp);
		if(!cb_in) {
			return ERROR;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			return ERROR;
		}

		if(ip->dst.value() == ntohl(cmsg->leftA)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control]: It's the left anchor.\n", ns.c_str());
#endif
			//DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);
			//DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
			DyscoHashOut* cb_out = cb_in->dcb_out;
			
			if(!cb_out) {
				return ERROR;
			}

			if(cb_out->state == DYSCO_ESTABLISHED) {
				// It is a retransmission
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control]: It's a retransmission packet. DYSCO_ESTABLISHED state.\n", ns.c_str());
#endif
				return END;
			}

			cb_in->in_iseq = tcp->seq_num.value();
			cb_in->in_iack = tcp->ack_num.value();
			//cb_out->out_iack = cb_in->in_iseq + 1;
			//cb_in->in_iack = htonl(tcp->ack_num.value());

			//TEST
			cb_in->lastSeq_ho = tcp->seq_num.value();
			cb_in->lastAck_ho = tcp->ack_num.value();
			/*
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] IMPORTANT\n", ns.c_str());
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in (sub_in: %s)\n", ns.c_str(), print_ss1(cb_in->sub));
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->in_iseq = %X, cb_in->in_iack = %X.\n", ns.c_str(), cb_in->in_iseq, cb_in->in_iack);
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->out_iseq = %X, cb_in->out_iack = %X.\n", ns.c_str(), cb_in->out_iseq, cb_in->out_iack);
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->in_iseq = %X, cb_out->in_iack = %X.\n", ns.c_str(), cb_out->in_iseq, cb_out->in_iack);
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->out_iseq = %X, cb_out->out_iack = %X.\n", ns.c_str(), cb_out->out_iseq, cb_out->out_iack);
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->lastAck_ho = %X, cb_in->lastAck_ho = %X.\n", ns.c_str(), cb_out->lastAck_ho, cb_in->lastAck_ho);
#endif




			if(cb_out->in_iack < cb_out->out_iack) {
				cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] sub: %s.\n", ns.c_str(), print_ss1(cb_out->sub));
				fprintf(stderr, "[%s][DyscoAgentIn-Control] sup: %s.\n", ns.c_str(), print_ss1(cb_out->sup));
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta1 = %X (%X - %X).\n", ns.c_str(), cb_out->ack_delta, cb_out->out_iack, cb_out->in_iack);
#endif
				cb_out->ack_add = 1;
			} else {
				cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] sub: %s.\n", ns.c_str(), print_ss1(cb_out->sub));
				fprintf(stderr, "[%s][DyscoAgentIn-Control] sup: %s.\n", ns.c_str(), print_ss1(cb_out->sup));
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta2 = %X (%X - %X).\n", ns.c_str(), cb_out->ack_delta, cb_out->in_iack, cb_out->out_iack);
#endif
				cb_out->ack_add = 0;
			}

			*/



			
			//not necessary
			cb_out->ack_cutoff = cmsg->seqCutoff;
			
			cb_out->valid_ack_cut = 1;

			// SEND ACK MESSAGE
			//TEST //TODO
			create_ack(pkt, ip, tcp);

			//TEST
			cb_out->out_iseq = tcp->seq_num.value();
			cb_out->out_iack = tcp->ack_num.value();
			if(cb_out->in_iseq < cb_out->out_iseq) {
				cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->seq_delta3 = %X (%X - %X).\n", ns.c_str(), cb_out->seq_delta, cb_out->out_iseq, cb_out->in_iseq);
#endif
				cb_out->seq_add = 1;
			} else {
				cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->seq_delta4 = %X (%X - %X).\n", ns.c_str(), cb_out->seq_delta, cb_out->in_iseq, cb_out->out_iseq);
#endif
				cb_out->seq_add = 0;
			}

			if(cb_out->in_iack < cb_out->out_iack) {
				cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta3 = %X (%X - %X).\n", ns.c_str(), cb_out->ack_delta, cb_out->out_iack, cb_out->in_iack);
#endif
				cb_out->ack_add = 1;
			} else {
				cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_out->ack_delta4 = %X (%X - %X).\n", ns.c_str(), cb_out->ack_delta, cb_out->in_iack, cb_out->out_iack);
#endif
				cb_out->ack_add = 0;
			}

			//rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->sup);
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_out->sup);
			if(!rcb) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control]: rcb is NULL (super: %s)\n", ns.c_str(), print_ss1(cb_out->sup));
#endif
				return ERROR;
			}

			if(!rcb->old_dcb) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control]: rcb->old_dcb is NULL.\n", ns.c_str());
#endif
				return ERROR;
			}
			
			if(!rcb->old_dcb->state_t) {
				DyscoHashOut* old_dcb = rcb->old_dcb;
				if(!old_dcb) {
#ifdef DEBUG_RECONFIG
					fprintf(stderr, "[%s][DyscoAgentIn-Control]: old_dcb is NULL.\n", ns.c_str());
#endif
					return ERROR;
				}

				if(old_dcb->state == DYSCO_SYN_SENT)
					old_dcb->state = DYSCO_ESTABLISHED;

				cmsg->seqCutoff = old_dcb->seq_cutoff;
			}

			if(rcb->new_dcb) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] updating lastSeq and lastAck in rcb->new_dcb.\n", ns.c_str());
#endif
				rcb->new_dcb->lastSeq_ho = tcp->seq_num.value();
				rcb->new_dcb->lastAck_ho = tcp->ack_num.value();
			}
			
			return TO_GATE_1;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control]: It isn't left anchor.\n", ns.c_str());
#endif		
			set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			return TO_GATE_0;
		}
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] DYSCO_ACK message.\n", ns.c_str());
#endif

		cb_in = dc->lookup_input(this->index, ip, tcp);
		if(!cb_in) {
			return ERROR;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			return ERROR;
		}

		rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->sup);

		if(!rcb) {
			return ERROR;
		}
		
		if(isRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] It's the right anchor.\n", ns.c_str());
#endif
			DyscoHashOut* old_out;
			DyscoHashOut* new_out;
			uint32_t old_out_ack_cutoff;

			cb_in->in_iseq = tcp->seq_num.value();
			cb_in->in_iack = tcp->ack_num.value();

#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->sub: %s.\n", ns.c_str(), print_ss1(cb_in->sub));
			fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->sup: %s.\n", ns.c_str(), print_ss1(cb_in->sup));
#endif

			if(cb_in->in_iseq < cb_in->out_iseq) {
				cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta5 = %X (%X - %X).\n", ns.c_str(), cb_in->seq_delta, cb_in->out_iseq, cb_in->in_iseq);
#endif
				cb_in->seq_add = 1;
			} else {
				cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq.\n", ns.c_str());	
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->seq_delta6 = %X (%X - %X).\n", ns.c_str(), cb_in->seq_delta, cb_in->in_iseq, cb_in->out_iseq);
#endif
				cb_in->seq_add = 0;
			}
			
			if(cb_in->in_iack < cb_in->out_iack) {
				cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta1 = %X (%X - %X).\n", ns.c_str(), cb_in->ack_delta, cb_in->out_iack, cb_in->in_iack);
#endif
				cb_in->ack_add = 1;
			} else {
				cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->ack_delta2 = %X (%X - %X).\n", ns.c_str(), cb_in->ack_delta, cb_in->in_iack, cb_in->out_iack);
#endif
				cb_in->ack_add = 0;
			}

			
			if(!rcb->old_dcb) {
				return ERROR;
			}
			
			old_out = rcb->old_dcb;
			if(!old_out->other_path) {
				return ERROR;
			}
			
			new_out = old_out->other_path;
			old_out_ack_cutoff = cmsg->seqCutoff;
			
			if(new_out->in_iack < new_out->out_iack) {
				uint32_t delta = new_out->out_iack - new_out->in_iack;
				old_out_ack_cutoff += delta;
			}

			if(old_out->state == DYSCO_ESTABLISHED)
				return END;

			if(!old_out->state_t) {
				old_out->ack_cutoff = old_out_ack_cutoff;
				old_out->valid_ack_cut = true;
				old_out->state = DYSCO_ESTABLISHED;
			}




#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->sub: %s.\n", ns.c_str(), print_ss1(new_out->sub));
			fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->sup: %s.\n", ns.c_str(), print_ss1(new_out->sup));
#endif

			if(new_out->in_iseq < new_out->out_iseq) {
				new_out->seq_delta = new_out->out_iseq - new_out->in_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->seq_delta = new_out->out_iseq - new_out->in_iseq.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->seq_delta5 = %X (%X - %X).\n", ns.c_str(), new_out->seq_delta, new_out->out_iseq, new_out->in_iseq);
#endif
				new_out->seq_add = 1;
			} else {
				new_out->seq_delta = new_out->in_iseq - new_out->out_iseq;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->seq_delta = new_out->in_iseq - new_out->out_iseq.\n", ns.c_str());	
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->seq_delta6 = %X (%X - %X).\n", ns.c_str(), new_out->seq_delta, new_out->in_iseq, new_out->out_iseq);
#endif
				new_out->seq_add = 0;
			}
			
			if(new_out->in_iack < new_out->out_iack) {
				new_out->ack_delta = new_out->out_iack - new_out->in_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->ack_delta = new_out->out_iack - new_out->in_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->ack_delta1 = %X (%X - %X).\n", ns.c_str(), new_out->ack_delta, new_out->out_iack, new_out->in_iack);
#endif
				new_out->ack_add = 1;
			} else {
				new_out->ack_delta = new_out->in_iack - new_out->out_iack;
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->ack_delta = new_out->in_iack - new_out->out_iack.\n", ns.c_str());
				fprintf(stderr, "[%s][DyscoAgentIn-Control] new_out->ack_delta2 = %X (%X - %X).\n", ns.c_str(), new_out->ack_delta, new_out->in_iack, new_out->out_iack);
#endif
				new_out->ack_add = 0;
			}






















			

			
			return END;
		}
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control] It isn't the right anchor.\n", ns.c_str());
#endif
		set_ack_number_out(this->index, tcp, cb_in);
		in_hdr_rewrite_csum(ip, tcp, cb_in);
		
		return TO_GATE_0;
	} else {
#ifdef DYSCO_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentIn-Control]: It isn't SYN, SYN/ACK or ACK messages.\n", ns.c_str());
#endif
	}

	/*
	  TODO: verify the necessity of this.
	case DYSCO_STATE_TRANSFERRED:
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[DyscoAgentIn]: DYSCO_STATE_TRANSFERRED message.\n");
#endif
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(!rcb)
			return END;

		// verify htonl
		if(isLeftAnchor(ip, cmsg)) {
			dc->replace_cb_leftA(rcb, cmsg);
		} else if(isRightAnchor(ip, cmsg)) {
			DyscoHashOut* cb_out = rcb->old_dcb;
			cb_out->state = DYSCO_ESTABLISHED;
		}

		break;
	}
	*/
	//skb modifies???
	return TO_GATE_0; //TEST should be END;
}



/*

 */

void DyscoAgentIn::process_arp(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	bess::utils::Arp* arp = reinterpret_cast<bess::utils::Arp*>(eth + 1);

	if(arp->opcode.value() == bess::utils::Arp::kRequest ||
	   arp->opcode.value() == bess::utils::Arp::kReply) {
		dc->update_mac(arp->sender_hw_addr, arp->sender_ip_addr);
	}
}

/*
  Only payload > 0
 */
void DyscoAgentIn::create_synack(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
		
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = 32;
	ip->id = be16_t(rand() % 65536);
	uint32_t payload_len = ip->length.value() - (ip->header_length << 2) - (tcp->offset << 2);
	ip->length = ip->length - be16_t(payload_len);

	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;
	tcp->ack_num = be32_t(tcp->seq_num.value() + 1);
	//tcp->seq_num = be32_t(rand() % 4294967296);
	tcp->seq_num = be32_t(255);
	tcp->flags |= Tcp::kAck;
	pkt->trim(payload_len);
}

void DyscoAgentIn::create_ack(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
		
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = 32;
	ip->id = be16_t(rand() % 65536);
	
	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;

	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = be32_t(tcp->ack_num.value());
	tcp->ack_num = be32_t(seqswap.value() + 1);
	tcp->flags = Tcp::kAck;
}


ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
