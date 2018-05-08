#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"
#include "dysco_port_out.h"

#define DEBUG 1
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
			switch(input(pkt, ip, tcp)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
			case TO_GATE_1:
				out_gates[1].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
			default:
				fprintf(stderr, "input method returns FALSE, or ERROR\n");
			}
		} else {
			switch(control_input(pkt, ip, tcp)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
			case TO_GATE_1:
				out_gates[1].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
			case END:
				fprintf(stderr, "3-way from Reconfiguration Session is DONE.\n\n");
				break;
			case ERROR:
				fprintf(stderr, "ERROR on control_input\n");
			default:
				break;
			}
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

		cb_in->in_iseq = tcp->seq_num.value();
		cb_in->in_iack = tcp->ack_num.value();

		fprintf(stderr, "sub_ss: %s (cb_in->in_iseq: %X) (cb_in->in_iack: %X)\n", print_ss1(cb_in->sub), cb_in->in_iseq, cb_in->in_iack);
		
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
	fprintf(stderr, "in_two_paths_ack method.\n");
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out) {
		fprintf(stderr, "cb_in->dcb_out is NULL\n");
		return false;
	}

	fprintf(stderr, "cb_in->dcb_out (sub: %s).\n", print_ss1(cb_out->sub));

	if(cb_out->old_path) {
		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
			fprintf(stderr, "puting cb_in->two_paths1 = 0 (sub: %s)\n", print_ss1(cb_in->sub));
		} else {
			fprintf(stderr, "dc->after([%X %X])_1.\n", cb_out->seq_cutoff, ack_seq);
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				fprintf(stderr, "dc->after(cb_out->seq_cutoff, ack_seq)_1 is FALSE.\n");
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
				fprintf(stderr, "puting cb_in->two_paths2 = 0 (sub: %s)\n", print_ss1(cb_in->sub));
			} else {
				fprintf(stderr, "dc->after(cb_out->seq_cutoff, ack_seq) is TRUE.\n");
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out) {
			fprintf(stderr, "cb_in->dcb_out->other_path is NULL\n");
			return false;
		}

		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
			fprintf(stderr, "puting cb_in->two_paths3 = 0 (sub: %s)\n", print_ss1(cb_in->sub));
		} else {
			fprintf(stderr, "dc->after([%X %X])_2.\n", cb_out->seq_cutoff, ack_seq);
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				fprintf(stderr, "dc->after(cb_out->seq_cutoff, ack_seq)_2 is FALSE [%X %X].\n", cb_out->seq_cutoff, ack_seq);
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
				fprintf(stderr, "puting cb_in->two_paths4 = 0 (sub: %s)\n", print_ss1(cb_in->sub));
			} else {
				fprintf(stderr, "dc->after(cb_out->other_path->seq_cutoff, ack_seq) is TRUE.\n");
			}
		}
	}

	return true;
}

//L.683
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in) {
	fprintf(stderr, "in_two_paths_data_seg method.\n");
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

			fprintf(stderr, "[BEFORE]old_out->ack_cutoff: %X\n", old_out->ack_cutoff);
			if(old_out->valid_ack_cut) {
				if(dc->before(seq, old_out->ack_cutoff))
					old_out->ack_cutoff = seq;
			} else {
				old_out->ack_cutoff = seq;
				old_out->valid_ack_cut = 1;
				fprintf(stderr, "[AFTER]old_out->valid_ack_cut: 1\n");
			}
			fprintf(stderr, "[AFTER]old_out->ack_cutoff: %X\n", old_out->ack_cutoff);
		}
	}

	return true;
}

//L.753
CONTROL_RETURN DyscoAgentIn::input(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] receives a new TCP SYN+PAYLOAD segment\n", ns.c_str());
#endif
			if(rx_initiation_new(pkt, ip, tcp))
				return TO_GATE_0;
		}
		
		return TO_GATE_0;
	}

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
		
		return TO_GATE_0;
	}

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "cb_in->sub: %s.\n", print_ss1(cb_in->sub));
	fprintf(stderr, "cb_in->sup: %s.\n", print_ss1(cb_in->sup));
	fprintf(stderr, "cb_in->in_iseq: %X.\n", cb_in->in_iseq);
	fprintf(stderr, "cb_in->in_iack: %X.\n", cb_in->in_iack);
	fprintf(stderr, "cb_in->out_iseq: %X.\n", cb_in->out_iseq);
	fprintf(stderr, "cb_in->out_iack: %X.\n", cb_in->out_iack);
	fprintf(stderr, "cb_in->seq_delta: %X.\n", cb_in->seq_delta);
	fprintf(stderr, "cb_in->ack_delta: %X.\n", cb_in->ack_delta);
#endif

	if(tcp->flags & Tcp::kFin) {
		fprintf(stderr, "It's FIN segment.\n");
		if(cb_in->two_paths) {
			fprintf(stderr, "Does have two paths.\n");
			if(cb_in->dcb_out) {
				fprintf(stderr, "cb_in->dcb_out (sub: %s) ", print_ss1(cb_in->dcb_out->sub));
				if(cb_in->dcb_out->old_path)
					fprintf(stderr, "is OLD_PATH. In this case, should DyscoAgentIn answer this FIN?\n");
				else {
					fprintf(stderr, "isn't OLD_PATH. In this case, just forward to host.\n");
				}
				if(cb_in->dcb_out->other_path) {
					fprintf(stderr, "cb_in->dcb_out->other_path (sub: %s) ", print_ss1(cb_in->dcb_out->other_path->sub));
					if(cb_in->dcb_out->other_path->old_path)
						fprintf(stderr, "is OLD_PATH\n");
					else
						fprintf(stderr, "isn't OLD_PATH\n");
				}
			}
		} else {
			fprintf(stderr, "Doesn't have two paths.\n");
			if(cb_in->dcb_out) {
				fprintf(stderr, "cb_in->dcb_out (sub: %s) ", print_ss1(cb_in->dcb_out->sub));
				if(cb_in->dcb_out->old_path) {
					fprintf(stderr, "is OLD_PATH. In this case, doesn't forward to host and should DyscoAgentIn answer?\n");
					create_finack(pkt, ip, tcp);
					fprintf(stderr, "creating FIN/ACK packet\n");
					//Should DyscoAgentIn wait last ACK?
					return TO_GATE_1;
				} else {
					fprintf(stderr, "isn't OLD_PATH.\n");
				}
			}
		}

	}

	if(cb_in->two_paths)
		if(!hasPayload(ip, tcp))
			in_two_paths_ack(tcp, cb_in);
	
	
	//TODO
	/*
	  if(cb_in->two_paths) 
		if(hasPayload(ip, tcp)) {
			if(!in_two_paths_data_seg(tcp, cb_in))
				return false;
		} else
			in_two_paths_ack(tcp, cb_in);
	*/
	
	in_hdr_rewrite_csum(ip, tcp, cb_in);

	return TO_GATE_0;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control input
*/

/*
  Ronaldo: only RightA calls this method.
 */
DyscoCbReconfig* DyscoAgentIn::insert_rcb_control_input(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	//TEST
	//rcb->super = cmsg->super;
	rcb->super = cmsg->rightSS;
	rcb->leftSS = cmsg->leftSS;
	rcb->rightSS = cmsg->rightSS;
	rcb->sub_in.sip = htonl(ip->src.value());
	rcb->sub_in.dip = htonl(ip->dst.value());
	rcb->sub_in.sport = htons(tcp->src_port.value());
	rcb->sub_in.dport = htons(tcp->dst_port.value());
	rcb->sub_out.sip = 0;

	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);
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

DyscoHashOut* DyscoAgentIn::build_cb_in_reverse(Ipv4*, DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();

	/*
	cb_out->sup.sip = rcb->super.dip;
	cb_out->sup.dip = rcb->super.sip;
	cb_out->sup.sport = rcb->super.dport;
	cb_out->sup.dport = rcb->super.sport;
	*/

	//Ronaldo: Again, RightA doesn't know about leftSS.
	cb_out->sup.sip = rcb->rightSS.dip;
	cb_out->sup.dip = rcb->rightSS.sip;
	cb_out->sup.sport = rcb->rightSS.dport;
	cb_out->sup.dport = rcb->rightSS.sport;

	//cb_out->sub.sip = htonl(ip->dst.value());
	//cb_out->sub.dip = htonl(ip->src.value());
	cb_out->sub.sip = rcb->sub_in.dip;
	cb_out->sub.dip = rcb->sub_in.sip;
	cb_out->sub.sport = rcb->sub_in.dport;
	cb_out->sub.dport = rcb->sub_in.sport;

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIack;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIseq;

	return cb_out;
}

bool DyscoAgentIn::compute_deltas_in(DyscoHashIn* cb_in, DyscoHashOut* old_out, DyscoCbReconfig* rcb) {
	cb_in->out_iseq = old_out->in_iack;
	cb_in->out_iack = old_out->in_iseq;
	
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentIn-Control] compute_deltas_in.\n", ns.c_str());
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->in_iseq: %X.\n", ns.c_str(), cb_in->in_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->in_iack: %X.\n", ns.c_str(), cb_in->in_iack);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->out_iseq: %X.\n", ns.c_str(), cb_in->out_iseq);
	fprintf(stderr, "[%s][DyscoAgentIn-Control] cb_in->out_iack: %X.\n", ns.c_str(), cb_in->out_iack);	
#endif
	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_in->seq_delta1 = %X (%X - %X).\n", cb_in->seq_delta, cb_in->out_iseq, cb_in->in_iseq);
#endif
		cb_in->seq_add = 1;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_in->seq_delta2 = %X (%X - %X).\n", cb_in->seq_delta, cb_in->in_iseq, cb_in->out_iseq);
#endif
		cb_in->seq_add = 0;
	}
	
	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_in->ack_delta1 = %X (%X - %X).\n", cb_in->ack_delta, cb_in->out_iack, cb_in->in_iack);
#endif
		cb_in->ack_add = 1;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_in->ack_delta2 = %X (%X - %X).\n", cb_in->ack_delta, cb_in->in_iack, cb_in->out_iack);
#endif
		cb_in->ack_add = 0;
	}

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
	cb_out->in_iseq = old_out->in_iseq;
	cb_out->in_iack = old_out->in_iack;

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
		fprintf(stderr, "cb_out->seq_delta1 = %X (%X - %X).\n", cb_out->seq_delta, cb_out->out_iseq, cb_out->in_iseq);
#endif
		cb_out->seq_add = 1;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_out->seq_delta2 = %X (%X - %X).\n", cb_out->seq_delta, cb_out->in_iseq, cb_out->out_iseq);
#endif
		cb_out->seq_add = 0;
	}

	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_out->ack_delta1 = %X (%X - %X).\n", cb_out->ack_delta, cb_out->out_iack, cb_out->in_iack);
#endif		
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_out->ack_delta2 = %X (%X - %X).\n", cb_out->ack_delta, cb_out->in_iack, cb_out->out_iack);
#endif	
		cb_out->ack_add = 0;
	}

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

	local_ss.sip = cmsg->rightSS.dip;
	local_ss.dip = cmsg->rightSS.sip;
	local_ss.sport = cmsg->rightSS.dport;
	local_ss.dport = cmsg->rightSS.sport;
	
	//TEST
	/*
	local_ss.sip = cmsg->super.dip;
	local_ss.dip = cmsg->super.sip;
	local_ss.sport = cmsg->super.dport;
	local_ss.dport = cmsg->super.sport;
	*/
	DyscoHashOut* old_out = dc->lookup_output_by_ss(this->index, &local_ss);
	if(!old_out) {
		delete cb_in;
		dc->remove_reconfig(this->index, rcb);
		delete rcb;

		return false;
	}

	cb_in->sup = cmsg->rightSS;
	compute_deltas_in(cb_in, old_out, rcb);
	compute_deltas_out(cb_out, old_out, rcb);

	cb_in->two_paths = 1;
	//cb_in->sup = cmsg->super;

	rcb->new_dcb = cb_out;
	rcb->old_dcb = old_out;
	cb_out->other_path = old_out;
	
	if(ntohl(cmsg->semantic) == STATE_TRANSFER)
		old_out->state_t = 1;
	
	return true;
}

CONTROL_RETURN DyscoAgentIn::control_reconfig_in(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, uint8_t*, DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;
	if(!isRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG		
		fprintf(stderr, "It isn't the right anchor.\n");
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
		fprintf(stderr, "not right anchor puting cb_in->two_paths = 0 (sub: %s)\n", print_ss1(cb_in->sub));
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "It's the right anchor.\n");
#endif	
		cb_in = new DyscoHashIn();
		
		cb_in->sub = rcb->sub_in;
		cb_in->out_iseq = rcb->leftIseq;
		cb_in->out_iack = rcb->leftIack;
		cb_in->seq_delta = cb_in->ack_delta = 0;
		//TEST
		cb_in->in_iseq = tcp->seq_num.value(); //When LeftA sends TCP SYN segment, TCP and ACK values are, respectively, ISN values.
		cb_in->in_iack = tcp->ack_num.value();;
				
		cb_in->is_reconfiguration = 1;
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
		cb_out = build_cb_in_reverse(ip, rcb);
		
		if(!cb_out) {
			delete cb_in;
			dc->remove_reconfig(this->index, rcb);
			delete rcb;
			
			return ERROR;
		}

		//TEST
		cb_in->dcb_out = cb_out;
		cb_out->dcb_in = cb_in;
		
		dc->insert_hash_input(this->index, cb_in);

		//TEST //TODO //Ronaldo
		create_synack(pkt, ip, tcp);
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "Creating SYN/ACK segment.\n");
#endif
		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out)) {
			fprintf(stderr, "error in control_config_rightA\n");
			return ERROR;
		}
		
		//replace_cb_rightA method from control_output
		DyscoHashOut* old_out = rcb->old_dcb;
		DyscoHashOut* new_out = rcb->new_dcb;
		uint32_t seq_cutoff = old_out->seq_cutoff;

		old_out->old_path = 1;
		old_out->state = DYSCO_SYN_RECEIVED;
		old_out->other_path = new_out;
		fprintf(stderr, "new_seq_cutoff: %X +/- %X\n", seq_cutoff, new_out->seq_delta);
		if(new_out->seq_add)
			seq_cutoff += new_out->seq_delta;
		else
			seq_cutoff -= new_out->seq_delta;

		//Not necessary because cmsg doesn't forward in SYN/ACK segments.
		//cmsg->seqCutoff = htonl(seq_cutoff);

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "TO_GATE_1.\n");
#endif	       
		
		return TO_GATE_1;
	}

	
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "Do nothing, follows regular algorithm and forwads it to host.\n");
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
	fprintf(stderr, "Setting cb_in and cb_out as reconfiguration.\n");
#endif
	memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
	remove_sc(pkt, ip, tcp);
	in_hdr_rewrite(ip, tcp, &cb_in->sup);

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "Removes payload, translates session and forwards to GATE 0 (Host).\n");
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
		fprintf(stderr, "DYSCO_SYN message.\n");
#endif
		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
		
		//rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->rightSS); //Ronaldo: RightA doesn't know about supss (or leftSS)
		if(rcb) {
			// It is a retransmission
			return IS_RETRANSMISSION;
		}

		rcb = insert_rcb_control_input(ip, tcp, cmsg);
		if(!rcb) {
			return ERROR;
		}

		return control_reconfig_in(pkt, ip, tcp, payload, rcb, cmsg);
		
	} else if(isTCPSYN(tcp) && isTCPACK(tcp)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "DYSCO_SYN_ACK message.\n");
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
			fprintf(stderr, "It's the left anchor.\n");
#endif
			DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);
			//DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
			//DyscoHashOut* cb_out = cb_in->dcb_out;
			
			if(!cb_out) {
				return ERROR;
			}

			if(cb_out->state == DYSCO_ESTABLISHED) {
				// It is a retransmission
				return IS_RETRANSMISSION;
			}

			//seqCutoff??? SYN/ACK doesn't load cmsg instead Dysco (with UDP)
			//cb_out->ack_cutoff = ntohl(cmsg->seqCutoff);

			cb_out->valid_ack_cut = 1;
			cb_out->ack_cutoff = cb_out->out_iack;
			
			/*
			 *
			 * OUTPUT SIDE
			 *
			 */

			
			//SEND ACK MESSAGE
			fprintf(stderr, "Creating ACK message\n");
			create_ack(pkt, ip, tcp);
			
			//rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->sup);
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_out->sup);
			if(!rcb) {
				return ERROR;
			}

			if(!rcb->old_dcb) {
				return ERROR;
			}

			//TEST
			//cb_in->is_reconfiguration = 0;
			//rcb->old_dcb->ack_cutoff = rcb->old_dcb->in_iack;//should be + delta (but, which delta value?)
			//rcb->old_dcb->valid_ack_cut = 1;
			
			if(!rcb->old_dcb->state_t) {
				DyscoHashOut* old_dcb = rcb->old_dcb;
				if(!old_dcb) {
					return ERROR;
				}

				if(old_dcb->state == DYSCO_SYN_SENT)
					old_dcb->state = DYSCO_ESTABLISHED;

				//cmsg->seqCutoff = old_dcb->seq_cutoff;
			}
			
			return TO_GATE_1;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It isn't left anchor.\n");
#endif		
			set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			return TO_GATE_0;
		}
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "DYSCO_ACK message.\n");
#endif

		cb_in = dc->lookup_input(this->index, ip, tcp);
		if(!cb_in) {
			fprintf(stderr, "error1\n");
			return ERROR;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			fprintf(stderr, "error2\n");
			return ERROR;
		}

		rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->sup);
		if(!rcb) {
			fprintf(stderr, "error3\n");
			return ERROR;
		}
		
		if(isRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's the right anchor.\n");
#endif
			//TEST
			cb_in->is_reconfiguration = 0;
			
			DyscoHashOut* old_out;
			DyscoHashOut* new_out;
			uint32_t old_out_ack_cutoff;
			
			if(!rcb->old_dcb) {
				return ERROR;
			}
			
			old_out = rcb->old_dcb;
			if(!old_out->other_path) {
				return ERROR;
			}
			
			new_out = old_out->other_path;

			//ACK message doesn't load cmsg instead Dysco (with UDP)
			//old_out_ack_cutoff = ntohl(cmsg->seqCutoff);
			old_out_ack_cutoff = cb_in->in_iseq;
			
			if(new_out->in_iack < new_out->out_iack) {
				uint32_t delta = new_out->out_iack - new_out->in_iack;
				old_out_ack_cutoff += delta;
			}

			if(old_out->state == DYSCO_ESTABLISHED)
				return END;

			if(!old_out->state_t) {
				old_out->ack_cutoff = old_out_ack_cutoff;
				old_out->valid_ack_cut = 1;
				old_out->state = DYSCO_ESTABLISHED;
			}

			return END;
		}
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "It isn't the right anchor.\n");
#endif
		set_ack_number_out(this->index, tcp, cb_in);
		in_hdr_rewrite_csum(ip, tcp, cb_in);
		
		return TO_GATE_0;
	} else {
#ifdef DYSCO_RECONFIG
		fprintf(stderr, "It isn't SYN, SYN/ACK or ACK messages.\n");
#endif
	}

	/*
	  TODO: verify
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
	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = seqswap + be32_t(1);
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

void DyscoAgentIn::create_finack(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
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
	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = seqswap + be32_t(1);
	tcp->flags |= Tcp::kAck;
}


ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
