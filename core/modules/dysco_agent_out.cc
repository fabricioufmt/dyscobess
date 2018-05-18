#include <netinet/tcp.h>

#include "../module_graph.h"
#include "dysco_agent_out.h"
#include "dysco_port_inc.h"

#ifdef DEBUG
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

char* print_ss2(DyscoTcpSession ss) {
	char* buf = (char*) malloc(1024);
	sprintf(buf, "%s:%u -> %s:%u",
		printip2(ntohl(ss.sip)), ntohs(ss.sport),
		printip2(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}
#endif

const Commands DyscoAgentOut::cmds = {
	{"get_info", "EmptyArg", MODULE_CMD_FUNC(&DyscoAgentOut::CommandInfo), Command::THREAD_UNSAFE}
};

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
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

	return CommandSuccess();
}

CommandResponse DyscoAgentOut::CommandInfo(const bess::pb::EmptyArg&) {
	if(get_port_information())
		return CommandSuccess();
	
	return CommandFailure(EINVAL, "ERROR: Port information.");
}

void DyscoAgentOut::ProcessBatch(bess::PacketBatch* batch) {
	if(!dc) {
		RunChooseModule(0, batch);
		return;
	}
	
	Ethernet* eth;
	bess::Packet* pkt;
	bess::PacketBatch toSend;
	toSend.clear();
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();
			
		if(!isIP(eth))
			continue;
			
		Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
		size_t ip_hlen = ip->header_length << 2;
		if(!isTCP(ip))
			continue;
			
		Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentOut] receives %s:%u -> %s:%u [%X:%X]\n",
			ns.c_str(),
			printip2(ip->src.value()), tcp->src_port.value(),
			printip2(ip->dst.value()), tcp->dst_port.value(),
			tcp->seq_num.value(), tcp->ack_num.value());
#endif
		DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);

		if(isReconfigPacket(ip, tcp, cb_out)) {
#ifdef DEBUG
			fprintf(stderr, "It's reconfiguration packet.\n");
#endif
			if(control_output(ip, tcp))
				dysco_packet(eth);

			dc->toRetransmit(this->index, devip, pkt);
			
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] forwards %s:%u -> %s:%u [%X:%X]\n\n",
				ns.c_str(),
				printip2(ip->src.value()), tcp->src_port.value(),
				printip2(ip->dst.value()), tcp->dst_port.value(),
				tcp->seq_num.value(), tcp->ack_num.value());
#endif


			continue;
		}
			
		if(output(pkt, ip, tcp, cb_out))
			dysco_packet(eth);

#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentOut] forwards %s:%u -> %s:%u [%X:%X]\n\n",
			ns.c_str(),
			printip2(ip->src.value()), tcp->src_port.value(),
			printip2(ip->dst.value()), tcp->dst_port.value(),
			tcp->seq_num.value(), tcp->ack_num.value());

		toSend.add(pkt);
#endif
	}
	
	batch.clear();
	
	//RunChooseModule(0, batch);
	RunChooseModule(0, &toSend);
}

bool DyscoAgentOut::get_port_information() {
	gate_idx_t igate_idx = 0; //always 1 input gate (DyscoPortInc)

	if(!is_active_gate<bess::IGate>(igates(), igate_idx))
		return false;

	bess::IGate* igate = igates()[igate_idx];
	if(!igate)
		return false;

	Module* m_prev = igate->ogates_upstream()[0]->module();
	DyscoPortInc* dysco_port_inc = reinterpret_cast<DyscoPortInc*>(m_prev);
	if(!dysco_port_inc)
		return false;

	DyscoVPort* dysco_vport = reinterpret_cast<DyscoVPort*>(dysco_port_inc->port_);
	if(!dysco_vport)
		return false;

	port = dysco_vport;
	ns = dysco_vport->ns;
	devip = dysco_vport->devip;
	index = dc->get_index(ns, devip);
	
	return true;
}

bool DyscoAgentOut::isReconfigPacket(Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(isTCPSYN(tcp, true)) {
		if(!cb_out) {
			uint32_t payload_len = hasPayload(ip, tcp);
			if(payload_len) {
				uint32_t tcp_hlen = tcp->offset << 2;
				
				if(((uint8_t*)tcp + tcp_hlen)[payload_len - 1] == 0xFF)
					return true;
			}

			return false;
		}

		if(!cb_out->dcb_in)
			return false;
			
		if(cb_out->dcb_in->is_reconfiguration)
			return true;
	}
		
	return false;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below.
 */

//L.365
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

//L.391
bool DyscoAgentOut::out_rewrite_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->ack_delta) {
		uint32_t new_ack;
		uint32_t ack = tcp->ack_num.value();

		if(cb_out->ack_add)
			new_ack = ack + cb_out->ack_delta;
		else
			new_ack = ack - cb_out->ack_delta;

		if(cb_out->sack_ok)
			dc->tcp_sack(tcp, cb_out->ack_delta, cb_out->ack_add);
		
		tcp->ack_num = be32_t(new_ack);

		return true;
	}

	return false;
}

//L.422
bool DyscoAgentOut::out_rewrite_ts(Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoTcpTs* ts = dc->get_ts_option(tcp);
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

//L.466
bool DyscoAgentOut::out_rewrite_rcv_wnd(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->ws_delta) {
		uint32_t wnd = tcp->window.value();

		wnd <<= cb_out->ws_in;
		wnd >>= cb_out->ws_out;
		tcp->window = be16_t(wnd);

		return true;
	}

	return false;
}

//L.492
DyscoHashOut* DyscoAgentOut::pick_path_seq(DyscoHashOut* cb_out, uint32_t seq) {
	DyscoHashOut* cb = cb_out;
	
	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			cb = cb_out->other_path;
		}
	} else if(cb_out->use_np_seq) {
		cb = cb_out->other_path;
	} else if(!dc->before(seq, cb_out->seq_cutoff)) {
		cb = cb_out->other_path;
	}

	return cb;
}

//L.519
DyscoHashOut* DyscoAgentOut::pick_path_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoHashOut* cb = cb_out;
	uint32_t ack = tcp->ack_num.value();
	
	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			cb = cb_out->other_path;
		}
	} else {
		if(cb_out->valid_ack_cut) {
			if(cb_out->use_np_ack) {
				cb = cb_out->other_path;
			} else if(!dc->after(cb_out->ack_cutoff, ack)) {		
				if(tcp->flags & Tcp::kFin)
					cb = cb_out->other_path;
				else {
					//TEST
					//tcp->ack_num = be32_t(cb_out->ack_cutoff);
					cb = cb_out->other_path;
					cb_out->ack_ctr++;
					if(cb_out->ack_ctr > 1)
						cb_out->use_np_ack = 1;
				}
			}
		}
	}
	return cb;
}

//L.585
bool DyscoAgentOut::out_translate(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t seg_sz = ip->length.value() - ip_hlen - tcp_hlen;
	uint32_t seq = tcp->seq_num.value() + seg_sz;

	DyscoHashOut* cb = cb_out;
	DyscoHashOut* other_path = cb_out->other_path;
	if(!other_path) {
		//TEST
		cb_out->seq_cutoff = seq;
		//if(seg_sz > 0 && dc->after(seq, cb_out->seq_cutoff))
		//	cb_out->seq_cutoff = seq;
	} else {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			if(seg_sz > 0)
				cb = pick_path_seq(cb_out, seq);
			else
				cb = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_SENT) {
			if(seg_sz > 0) {
				if(dc->after(seq, cb_out->seq_cutoff))
					cb_out->seq_cutoff = seq;
			} else
				cb = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_RECEIVED) {
			if(seg_sz > 0) {
				cb = pick_path_seq(cb_out, seq);
				//if(!cb_out->old_path)

			} else
				cb = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_CLOSED) {
			//TEST
			//Should forward to other_path
			if(cb_out->other_path)
				cb = cb_out->other_path;
		}
	}

	out_rewrite_seq(tcp, cb);
	out_rewrite_ack(tcp, cb);

	if(cb->ts_ok)
		out_rewrite_ts(tcp, cb);

	if(cb->ws_ok)
		out_rewrite_rcv_wnd(tcp, cb);

	dc->out_hdr_rewrite(pkt, ip, tcp, &cb->sub);
	
	return true;
}

//L.1089
bool DyscoAgentOut::update_five_tuple(Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out)
		return false;
	
	cb_out->sup.sip = htonl(ip->src.value());
	cb_out->sup.dip = htonl(ip->dst.value());
	cb_out->sup.sport = htons(tcp->src_port.value());
	cb_out->sup.dport = htons(tcp->dst_port.value());
	
	return true;
}

//L.1395
bool DyscoAgentOut::output(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb) {
	DyscoHashOut* cb_out = cb;
	if(!cb_out) {
		cb_out = dc->lookup_output_pending(this->index, ip, tcp);
		if(cb_out) {
			return dc->out_handle_mb(this->index, pkt, ip, tcp, cb_out, devip);
		}

		cb_out = dc->lookup_pending_tag(this->index, tcp);
		if(cb_out) {
			update_five_tuple(ip, tcp, cb_out);
			
			return dc->out_handle_mb(this->index, pkt, ip, tcp, cb_out, devip);
		}
	}

	if(isTCPSYN(tcp)) {
		return dc->out_syn(this->index, pkt, ip, tcp, cb_out, devip) != 0 ? true : false;
	}

	if(!cb_out) {
		return false;
	}
	
	out_translate(pkt, ip, tcp, cb_out);

	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control output
*/

DyscoCbReconfig* DyscoAgentOut::insert_cb_control(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->leftSS;
	rcb->sub_out.sip = htonl(ip->src.value());
	rcb->sub_out.dip = htonl(ip->dst.value());
	rcb->sub_out.sport = htons(tcp->src_port.value());
	rcb->sub_out.dport = htons(tcp->dst_port.value());
	
	rcb->leftIseq = ntohl(cmsg->leftIseq);
	rcb->leftIack = ntohl(cmsg->leftIack);
	rcb->leftIts = ntohl(cmsg->leftIts);
	rcb->leftItsr = ntohl(cmsg->leftItsr);
	rcb->leftIws = ntohl(cmsg->leftIws);
	rcb->leftIwsr = ntohl(cmsg->leftIwsr);
	rcb->sack_ok = ntohl(cmsg->sackOk);

	if(!dc->insert_hash_reconfig(this->index, rcb))
		return 0;
	
	return rcb;
}

bool DyscoAgentOut::control_insert_out(DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();

	cb_out->sup = rcb->super;
	cb_out->sub = rcb->sub_out;

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIseq;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIack;

	cb_out->ts_out = cb_out->ts_in = rcb->leftIts;
	cb_out->tsr_out = cb_out->tsr_in = rcb->leftItsr;

	cb_out->ws_out = cb_out->ws_in = rcb->leftIws;

	cb_out->sack_ok = rcb->sack_ok;

	dc->insert_cb_out(this->index, cb_out, 0);

	DyscoHashIn* cb_in = cb_out->dcb_in;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_out;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_out;

	return true;
}

bool DyscoAgentOut::replace_cb_rightA(DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

	if(!rcb)
		return false;

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

	cmsg->seqCutoff = htonl(seq_cutoff);

	return true;
}

bool DyscoAgentOut::replace_cb_leftA(DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashOut* old_dcb = rcb->old_dcb;

	if(old_dcb->state == DYSCO_SYN_SENT)
		old_dcb->state = DYSCO_ESTABLISHED;

	cmsg->seqCutoff = htonl(old_dcb->seq_cutoff);

	return true;
}

bool DyscoAgentOut::control_output_syn(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);
	
	if(isFromLeftAnchor(ip, cmsg)) {
#ifdef DEBUG
		fprintf(stderr, "It's the left anchor.\n");
#endif
		DyscoHashOut* old_dcb;
		DyscoHashOut* new_dcb;

		if(rcb) {
			cmsg->leftIseq = htonl(rcb->leftIseq);
			cmsg->leftIack = htonl(rcb->leftIack);

			cmsg->leftIts = htonl(rcb->leftIts);
			cmsg->leftItsr = htonl(rcb->leftItsr);

			cmsg->leftIws = htons(rcb->leftIws);
			cmsg->leftIwsr = htonl(rcb->leftIwsr);

			cmsg->sackOk = htons(rcb->sack_ok);

			cmsg->sport = rcb->sub_out.sport;
			cmsg->dport = rcb->sub_out.dport;
			
			return true;
		}
		
		old_dcb = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);

		if(!old_dcb) {
			return false;
		}

		tcp->seq_num = be32_t(old_dcb->out_iseq);
		tcp->ack_num = be32_t(old_dcb->out_iack);
		cmsg->leftIseq = htonl(old_dcb->out_iseq);
		cmsg->leftIack = htonl(old_dcb->out_iack);

		cmsg->leftIts = htonl(old_dcb->ts_in);
		cmsg->leftItsr = htonl(old_dcb->tsr_in);

		cmsg->leftIws = htonl(old_dcb->ws_in);
		if(old_dcb->dcb_in)
			cmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);

		cmsg->sackOk = htonl(old_dcb->sack_ok);
		
		rcb = insert_cb_control(ip, tcp, cmsg);
		if(!rcb) {
			return false;
		}

		new_dcb = new DyscoHashOut();

		rcb->old_dcb = old_dcb;
		rcb->new_dcb = new_dcb;

		new_dcb->sup = rcb->super;
		new_dcb->sub = rcb->sub_out;

		new_dcb->in_iack = old_dcb->in_iack;
		new_dcb->out_iseq = old_dcb->out_iseq;
		new_dcb->out_iack = old_dcb->out_iack;
		
		new_dcb->ts_out = new_dcb->ts_in = rcb->leftIts;
		new_dcb->tsr_out = new_dcb->tsr_in = rcb->leftItsr;

		new_dcb->ws_out = new_dcb->ws_in = rcb->leftIws;

		new_dcb->ts_ok = rcb->leftIts? 1 : 0;
		new_dcb->ws_ok = rcb->leftIws? 1 : 0;

		new_dcb->sack_ok = rcb->sack_ok;

		old_dcb->other_path = new_dcb;
		new_dcb->other_path = old_dcb;
		new_dcb->dcb_in = dc->insert_cb_out_reverse(this->index, new_dcb, 1, cmsg);

		if(new_dcb->dcb_in) {
			new_dcb->dcb_in->is_reconfiguration = 1;
		}
		
		memcpy(&new_dcb->cmsg, cmsg, sizeof(DyscoControlMessage));
		new_dcb->is_reconfiguration = 1;

		old_dcb->old_path = 1;

		if(ntohs(cmsg->semantic) == STATE_TRANSFER)
			old_dcb->state_t = 1;

		old_dcb->state = DYSCO_SYN_SENT;

		return true;
	}
#ifdef DEBUG
	fprintf(stderr, "It isn't the left anchor.\n");
#endif
	if(rcb && rcb->sub_out.sip != 0)
		return true;

	rcb = insert_cb_control(ip, tcp, cmsg);
	if(!rcb)
		return false;

	control_insert_out(rcb);

	return true;
}

bool DyscoAgentOut::control_output(Ipv4* ip, Tcp* tcp) {
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + (tcp->offset << 2);

	return control_output_syn(ip, tcp, reinterpret_cast<DyscoControlMessage*>(payload));
}

void DyscoAgentOut::dysco_packet(Ethernet* eth) {
	eth->dst_addr.FromString(DYSCO_MAC);
}

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming from host")






