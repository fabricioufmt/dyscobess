#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"
#include "dysco_port_out.h"

#ifdef DEBUG
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
#endif

void worker(DyscoAgentIn* agent) {
	std::Packet* pkt;
	std::PacketBatch batch;
	std::vector<NodeRetransmission>* list;
	std::chrono::system_clock::time_point ts;
	
	while(1) {
		batch.clear();
		usleep(SLEEPTIME); //1000 usec = 1ms
		list = agent->getRetransmissionList();

		if(!list)
			continue;
		
		if(list->empty())
			continue;

		for(std::vector<NodeRetransmission>::iterator it = list->begin(); it != list->end(); it++) {
			ts = it->ts;
			pkt = it->pkt;

			if(didIReceive(pkt)) {
				list->erase(it);
			} else {/*
				if(ts == 0)
					batch.add(pkt);
					else if(std::chrono::system_clock::now() - ts > agent->getTimeout())*/
					batch.add(pkt);
			}
			
		}

		agent->runRetransmission(&batch);	
	}
}

const Commands DyscoAgentIn::cmds = {
	{"get_info", "EmptyArg", MODULE_CMD_FUNC(&DyscoAgentIn::CommandInfo), Command::THREAD_UNSAFE}
};
	
DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
	timeout = 10000; //Default value
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

		DyscoHashIn* cb_in = dc->lookup_input(this->index, ip, tcp);
		
		if(!isReconfigPacket(ip, tcp, cb_in)) {
			switch(input(pkt, ip, tcp, cb_in)) {
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
#ifdef DEBUG
				fprintf(stderr, "Neither Gate0 or Gate1\n\n");
#endif
				break;
			}
		} else {
			//should update received list
			receivedList.push_back(*tcp);
			switch(control_input(pkt, ip, tcp, cb_in)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
			case TO_GATE_1:
				/*
				out_gates[1].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n", ns.c_str(), printip1(ip->src.value()), tcp->src_port.value(), printip1(ip->dst.value()), tcp->dst_port.value(), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				*/
				dc->toRetransmit(this->index, devip, pkt);
				break;
			case END:
#ifdef DEBUG
				fprintf(stderr, "3-way from Reconfiguration Session is DONE.\n\n");
#endif
				break;
			case ERROR:
#ifdef DEBUG
				fprintf(stderr, "ERROR on control_input\n");
#endif
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

	ns = dysco_vport->ns;
	devip = dysco_vport->devip;
	index = dc->get_index(ns, devip);
	
	port = dysco_vport;
	
	return true;
}

bool DyscoAgentIn::isReconfigPacket(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(isTCPSYN(tcp, true)) {
		if(!cb_in) {
			uint32_t payload_len = hasPayload(ip, tcp);
			if(payload_len) {
				uint32_t tcp_hlen = tcp->offset << 2;
				
				if(((uint8_t*)tcp + tcp_hlen)[payload_len - 1] == 0xFF)
					return true;
			}
		}
		
		return false;
	}

	if(!cb_in)
		return false;
	
	if((isTCPSYN(tcp) && isTCPACK(tcp)) || isTCPACK(tcp, true)) {
		if(cb_in->is_reconfiguration) {
			return true;
		}
		
		//Should consider state
	}

	return false;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below.
*/
bool DyscoAgentIn::remove_sc(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t payload_sz = ip->length.value() - ip_hlen - tcp_hlen;

	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);

	return true;
}

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
	}

	if(cb_in->tsr_delta) {
		if(cb_in->tsr_add)
			new_tsr = ntohl(ts->tsr) + cb_in->tsr_delta;
		else
			new_tsr = ntohl(ts->tsr) - cb_in->tsr_delta;

		new_tsr = htonl(new_tsr);
		ts->tsr = new_tsr;
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

		remove_sc(pkt, ip, tcp);
		dc->parse_tcp_syn_opt_r(tcp, cb_in);
		dc->insert_tag(this->index, pkt, ip, tcp);
		in_hdr_rewrite(ip, tcp, &cb_in->sup);
	}
	
	return true;
}

//L.614
bool DyscoAgentIn::in_two_paths_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out) {
		return false;
	}
	
	if(cb_out->old_path) {
		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
		} else {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out) {
			return false;
		}

		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
		} else {
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
CONTROL_RETURN DyscoAgentIn::input(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
			if(rx_initiation_new(pkt, ip, tcp))
				return TO_GATE_0;
		}
		
		return TO_GATE_0;
	}

	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			dc->set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);
		} else {
			//It is retransmission packet, just remove sc (if there is) and insert Dysco Tag
			if(hasPayload(ip, tcp)) {
				remove_sc(pkt, ip, tcp);
				dc->insert_tag(this->index, pkt, ip, tcp);
				in_hdr_rewrite(ip, tcp, &cb_in->sup);
			}
		}
		
		return TO_GATE_0;
	}

	if(tcp->flags & Tcp::kFin) {
		if(!cb_in->two_paths) {
			if(cb_in->dcb_out && cb_in->dcb_out->old_path) {
				create_finack(pkt, ip, tcp);
				cb_in->dcb_out->state = DYSCO_LAST_ACK;
				
				return TO_GATE_1;
			}
		}

	}

	if(cb_in->two_paths) {
		if(!hasPayload(ip, tcp))
			in_two_paths_ack(tcp, cb_in);
	} else {
		if(tcp->flags == Tcp::kAck && cb_in->dcb_out && cb_in->dcb_out->state == DYSCO_LAST_ACK) {
			//Should consider ACK value to close
#ifdef DEBUG
			fprintf(stderr, "old path was closed.\n");
#endif
			cb_in->dcb_out->state = DYSCO_CLOSED;
			
			return END;
		}
	}
	
	
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
	
	//Ronaldo: Again, RightA doesn't know about leftSS.
	cb_out->sup.sip = rcb->rightSS.dip;
	cb_out->sup.dip = rcb->rightSS.sip;
	cb_out->sup.sport = rcb->rightSS.dport;
	cb_out->sup.dport = rcb->rightSS.sport;

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
	
#ifdef DEBUG
	fprintf(stderr, "compute_deltas_in.\n");
	fprintf(stderr, "cb_in->in_iseq: %X.\n", cb_in->in_iseq);
	fprintf(stderr, "cb_in->in_iack: %X.\n", cb_in->in_iack);
	fprintf(stderr, "cb_in->out_iseq: %X.\n", cb_in->out_iseq);
	fprintf(stderr, "cb_in->out_iack: %X.\n", cb_in->out_iack);	
#endif
	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
#ifdef DEBUG
		fprintf(stderr, "cb_in->seq_delta1 = %X (%X - %X).\n", cb_in->seq_delta, cb_in->out_iseq, cb_in->in_iseq);
#endif
		cb_in->seq_add = 1;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
#ifdef DEBUG
		fprintf(stderr, "cb_in->seq_delta2 = %X (%X - %X).\n", cb_in->seq_delta, cb_in->in_iseq, cb_in->out_iseq);
#endif
		cb_in->seq_add = 0;
	}
	
	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
#ifdef DEBUG
		fprintf(stderr, "cb_in->ack_delta1 = %X (%X - %X).\n", cb_in->ack_delta, cb_in->out_iack, cb_in->in_iack);
#endif
		cb_in->ack_add = 1;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
#ifdef DEBUG
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

#ifdef DEBUG
	fprintf(stderr, "compute_deltas_out.\n");
	fprintf(stderr, "cb_out->in_iseq: %X.\n", cb_out->in_iseq);
	fprintf(stderr, "cb_out->in_iack: %X.\n", cb_out->in_iack);
	fprintf(stderr, "cb_out->out_iseq: %X.\n", cb_out->out_iseq);
	fprintf(stderr, "cb_out->out_iack: %X.\n", cb_out->out_iack);
#endif
	
	if(cb_out->in_iseq < cb_out->out_iseq) {
		cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
#ifdef DEBUG
		fprintf(stderr, "cb_out->seq_delta1 = %X (%X - %X).\n", cb_out->seq_delta, cb_out->out_iseq, cb_out->in_iseq);
#endif
		cb_out->seq_add = 1;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
#ifdef DEBUG
		fprintf(stderr, "cb_out->seq_delta2 = %X (%X - %X).\n", cb_out->seq_delta, cb_out->in_iseq, cb_out->out_iseq);
#endif
		cb_out->seq_add = 0;
	}

	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
#ifdef DEBUG
		fprintf(stderr, "cb_out->ack_delta1 = %X (%X - %X).\n", cb_out->ack_delta, cb_out->out_iack, cb_out->in_iack);
#endif		
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
#ifdef DEBUG
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

	size_t tcp_hlen = tcp->offset << 2;
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_sz = ip->length.value() - (ip->header_length << 2) - tcp_hlen;
		
	if(isToRightAnchor(ip, cmsg)) {
#ifdef DEBUG
		fprintf(stderr, "It's the right anchor.\n");
#endif	
		cb_in = new DyscoHashIn();
		
		cb_in->sub = rcb->sub_in;
		cb_in->out_iseq = rcb->leftIseq;
		cb_in->out_iack = rcb->leftIack;
		cb_in->seq_delta = cb_in->ack_delta = 0;

		//When LeftA sends TCP SYN segment, TCP and ACK values are, respectively, ISN values of the session.
		cb_in->in_iseq = tcp->seq_num.value();
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

		cb_in->dcb_out = cb_out;
		cb_out->dcb_in = cb_in;
		
		dc->insert_hash_input(this->index, cb_in);

		create_synack(pkt, ip, tcp);
		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out)) {
			return ERROR;
		}
		
		//replace_cb_rightA method from control_output
		DyscoHashOut* old_out = rcb->old_dcb;
		DyscoHashOut* new_out = rcb->new_dcb;
		uint32_t seq_cutoff = old_out->seq_cutoff;

		old_out->old_path = 1;
		old_out->state = DYSCO_SYN_RECEIVED;
		old_out->other_path = new_out;
		
		if(new_out->seq_add)
			seq_cutoff += new_out->seq_delta;
		else
			seq_cutoff -= new_out->seq_delta;

		return TO_GATE_1;
	}

#ifdef DEBUG
	fprintf(stderr, "It isn't the right anchor.\n");
#endif

	cb_in = dc->insert_cb_input(this->index, ip, tcp, payload, payload_sz);
	if(!cb_in)
		return ERROR;
		
	cb_in->in_iseq = rcb->leftIseq;
	cb_in->in_iack = rcb->leftIack;
	cb_in->two_paths = 0;

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

	cb_in->is_reconfiguration = 1;
	cb_in->dcb_out->is_reconfiguration = 1;
	
	memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));

	uint32_t sc_len = (payload_sz - sizeof(DyscoControlMessage) - 1)/sizeof(uint32_t); //-1 for 0xFF tag
	uint32_t* sc = (uint32_t*)(payload + sizeof(DyscoControlMessage));
		
	if(ntohs(cmsg->semantic) == NOSTATE_TRANSFER || sc_len < 2) {
#ifdef DEBUG
		fprintf(stderr, "NOSTATE_TRANSFER.\n");
#endif
		remove_sc(pkt, ip, tcp);
		in_hdr_rewrite(ip, tcp, &cb_in->sup);
	
		return TO_GATE_0;
	}

	//STATE_TRANSFER
#ifdef DEBUG
	fprintf(stderr, "STATE_TRANSFER.\n");
	fprintf(stderr, "super: %s.\n", print_ss1(cmsg->super));
	fprintf(stderr, "leftSS: %s.\n", print_ss1(cmsg->leftSS));
	fprintf(stderr, "rightSS: %s.\n", print_ss1(cmsg->rightSS));
#endif
	
	cb_in->state = DYSCO_SYN_RECEIVED;
	cb_in->dcb_out->state = DYSCO_SYN_SENT;
	if(isTCPSYN(tcp, true)) {
		ip->length = ip->length - be16_t(sizeof(uint32_t));
		pkt->trim(sizeof(uint32_t));
		
		ip->src = ip->dst;
		ip->dst = be32_t(ntohl(sc[1]));

		memcpy(payload + sizeof(DyscoControlMessage), payload + sizeof(DyscoControlMessage) + 4, (sc_len - 1) * sizeof(uint32_t));
		payload[sizeof(DyscoControlMessage) + (sc_len - 1) * sizeof(uint32_t)] = 0xFF;
			
		ip->checksum = 0;
		tcp->checksum = 0;
		ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
		tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
		/*
		DyscoHashIn* cb_in2 = new DyscoHashIn();
		DyscoHashOut* cb_out2 = new DyscoHashOut();
		if(!cb_in2)
			return ERROR;

		cb_in2->state = DYSCO_SYN_RECEIVED;
		cb_in2->sub.sip = htonl(ip->dst.value());
		cb_in2->sub.dip = htonl(ip->src.value());
		cb_in2->sub.sport = htons(tcp->dst_port.value());
		cb_in2->sub.dport = htons(tcp->src_port.value());

		cb_in2->sup
		

		DyscoHashes* dh = get_hash(this->index);
		if(!dh)
			return ERROR;

		dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn*>(cb_in2->sub, cb_in2));
		*/
		return TO_GATE_1;
	}

	return TO_GATE_1;
}

CONTROL_RETURN DyscoAgentIn::control_input(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg = 0;
	size_t tcp_hlen = tcp->offset << 2;
	
	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG
		fprintf(stderr, "DYSCO_SYN message.\n");
#endif
		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
		
		//rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);
		//Ronaldo: RightA doesn't know about supss (or leftSS)
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->rightSS); 
		if(rcb) {
			return IS_RETRANSMISSION;
		}

		rcb = insert_rcb_control_input(ip, tcp, cmsg);
		if(!rcb) {
			return ERROR;
		}

		return control_reconfig_in(pkt, ip, tcp, payload, rcb, cmsg);
		
	} else if(isTCPSYN(tcp) && isTCPACK(tcp)) {
#ifdef DEBUG
		fprintf(stderr, "DYSCO_SYN_ACK message.\n");
#endif

		if(!cb_in) {
			return ERROR;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			return ERROR;
		}

		if(ip->dst.value() == ntohl(cmsg->leftA)) {
#ifdef DEBUG
			fprintf(stderr, "It's the left anchor.\n");
#endif
			DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);
			if(!cb_out) {
				return ERROR;
			}

			if(cb_out->state == DYSCO_ESTABLISHED) {
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

			create_ack(pkt, ip, tcp);
			
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_out->sup);
			if(!rcb) {
				return ERROR;
			}

			if(!rcb->old_dcb) {
				return ERROR;
			}

			cb_in->is_reconfiguration = 0;
			
			if(!rcb->old_dcb->state_t) {
				DyscoHashOut* old_dcb = rcb->old_dcb;
				if(!old_dcb) {
					return ERROR;
				}

				if(old_dcb->state == DYSCO_SYN_SENT)
					old_dcb->state = DYSCO_ESTABLISHED;
			}
			
			return TO_GATE_1;
		} else {
#ifdef DEBUG
			fprintf(stderr, "It isn't left anchor.\n");
#endif		
			dc->set_ack_number_out(this->index, tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			return TO_GATE_0;
		}
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG
		fprintf(stderr, "DYSCO_ACK message.\n");
#endif

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
		
		if(isToRightAnchor(ip, cmsg)) {
#ifdef DEBUG
			fprintf(stderr, "It's the right anchor.\n");
#endif

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
#ifdef DEBUG
		fprintf(stderr, "It isn't the right anchor.\n");
#endif
		dc->set_ack_number_out(this->index, tcp, cb_in);
		in_hdr_rewrite_csum(ip, tcp, cb_in);
		
		return TO_GATE_0;
	}

	/*
	  TODO: verify
	case DYSCO_STATE_TRANSFERRED:
#ifdef DEBUG
		fprintf(stderr, "[DyscoAgentIn]: DYSCO_STATE_TRANSFERRED message.\n");
#endif
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

		if(!rcb)
			return END;

		// verify htonl
		if(isToLeftAnchor(ip, cmsg)) {
			dc->replace_cb_leftA(rcb, cmsg);
		} else if(isToRightAnchor(ip, cmsg)) {
			DyscoHashOut* cb_out = rcb->old_dcb;
			cb_out->state = DYSCO_ESTABLISHED;
		}

		break;
	}
	*/
	
	return END;
}

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

/*
  TCP Retransmission methods
 */
std::vector<NodeRetransmission>* DyscoAgentIn::getRetransmissionList() {
	if(!dc)
		return 0;

	return dc->getRetransmissionList(this->index, devip);
}

bool DyscoAgentIn::didIReceive(Ipv4* ip, Tcp* tcp) {
	Tcp* received;
	be32_t shouldReceived = tcp->seq_num + be32_t(hasPayload(ip, tcp));
	
	for(std::vector<Tcp>::iterator it = receivedList.begin(); it != receivedList.end(); it++) {
		received = it;

		if(received->ack_num == shouldReceived)
			return true;
	}
	
	return false;
}

void DyscoAgentIn::runRetransmission(bess::Packetbatch* batch) {
	RunChooseModule(1, batch);
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
