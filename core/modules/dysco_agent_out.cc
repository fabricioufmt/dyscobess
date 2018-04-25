#include "set_metadata.h"

#include <netinet/tcp.h>
#include "dysco_agent_out.h"
#include "../module_graph.h"
#include "dysco_port_inc.h"

#define DEBUG 1
#define DEBUG_RECONFIG 1

//debug
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

void print_out2(std::string ns, Ipv4* ip, Tcp* tcp) {
	fprintf(stderr, "[%s][DyscoAgentOut] forwards %s:%u -> %s:%u\n\n",
		ns.c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value());
}

const Commands DyscoAgentOut::cmds = {
	{"get_info", "EmptyArg", MODULE_CMD_FUNC(&DyscoAgentOut::CommandInfo), Command::THREAD_UNSAFE}
};

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	devip = 0;
	index = 0;

	netns_fd_ = 0;
	info_flag = false;
	//memset(ns, 0, sizeof(ns));
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
		fprintf(stderr, "[%s][DyscoAgentOut] receives %s:%u -> %s:%u [%u:%u]\n",
			ns.c_str(),
			printip2(ip->src.value()), tcp->src_port.value(),
			printip2(ip->dst.value()), tcp->dst_port.value(),
			ntohl(tcp->seq_num.value()), ntohl(tcp->ack_num.value()));
#endif
		if(isReconfigPacket(ip, tcp)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] It's reconfiguration packet.\n", ns.c_str());
#endif
			if(control_output(ip, tcp))
				dysco_packet(eth);

#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] forwards %s:%u -> %s:%u [%u:%u]\n\n",
				ns.c_str(),
				printip2(ip->src.value()), tcp->src_port.value(),
				printip2(ip->dst.value()), tcp->dst_port.value(),
				ntohl(tcp->seq_num.value()), ntohl(tcp->ack_num.value()));
#endif
				
			continue;
		}
			
		if(output(pkt, ip, tcp))
			dysco_packet(eth);

#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentOut] forwards %s:%u -> %s:%u [%u:%u]\n\n",
			ns.c_str(),
			printip2(ip->src.value()), tcp->src_port.value(),
			printip2(ip->dst.value()), tcp->dst_port.value(),
			ntohl(tcp->seq_num.value()), ntohl(tcp->ack_num.value()));
#endif
	}
	
	RunChooseModule(0, batch);
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

//L.62
//fix_tcp_ip_csum method -- in DyscoCenter

//L.98
//remove_tag method -- in DyscoCenter

//L.120
//tcp_sack_csum method
//Ronaldo: is it really necessary?

//L.219
//tcp_sack method -- in DyscoCenter

//L.295
//out_hdr_rewrite method -- in DyscoCenter

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
	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED)
			cb_out = cb_out->other_path;
	} else if(cb_out->use_np_seq) {
		cb_out = cb_out->other_path;
	} else if(!dc->before(seq, cb_out->seq_cutoff))
		cb_out = cb_out->other_path;

	return cb_out;
}

//L.519
DyscoHashOut* DyscoAgentOut::pick_path_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t ack = tcp->ack_num.value();

	if(cb_out->state_t) {
		if(cb_out->state == DYSCO_ESTABLISHED)
			cb_out = cb_out->other_path;
	} else if(cb_out->valid_ack_cut) {
		if(cb_out->use_np_ack) {
			cb_out = cb_out->other_path;
		} else if(!dc->after(cb_out->ack_cutoff, ack)) {
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

//L.585
bool DyscoAgentOut::out_translate(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t seg_sz = ip->length.value() - ip_hlen - tcp_hlen;
	uint32_t seq = tcp->seq_num.value() + seg_sz;

	DyscoHashOut* other_path = cb_out->other_path;
	if(!other_path) {
		if(seg_sz > 0 && dc->after(seq, cb_out->seq_cutoff))
			cb_out->seq_cutoff = seq;
	} else {
		if(cb_out->state == DYSCO_ESTABLISHED) {
			if(seg_sz > 0)
				cb_out = pick_path_seq(cb_out, seq);
			else
				cb_out = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_SENT) {
			if(seg_sz > 0) {
				if(dc->after(seq, cb_out->seq_cutoff))
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

	//dc->out_hdr_rewrite(ip, tcp, &cb_out->sub);
	if(dc->out_hdr_rewrite(pkt, ip, tcp, &cb_out->sub)) {
		/*
		uint32_t val = 1;
		const void* val_ptr = &val;
		void* mt_ptr = _ptr_attr_with_offset<value_t>(0, pkt);
		bess::utils::CopySmall(mt_ptr, val_ptr, sizeof(uint32_t));
		*/
	}
	
	return true;
}

//L.714
//add_sc -- in DyscoCenter

//L.756
//out_tx_init -- in DyscoCenter

//L.755
//match_policy -- in DyscoCenter

//L.806
//same_subnet -- not using

//L.822
//arp -- not using

//L.876
//create_cb_out -- in DyscoCenter

//L.919
//insert_cb_out_reverse -- in DyscoCenter

//L.985
//insert_cb_out -- in DyscoCenter

//L.1001
//out_lookup method -- in DyscoCenter

//L.1023
//lookup_pending method -- in DyscoCenter

//L.1046
//lookup_pending_tag method -- in DyscoCenter

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

//L.1111
//out_handle_mb method -- in DyscoCenter

//L.1156
//out_syn method -- in DyscoCenter

//L.1257
//fix_rcv_window

//L.1318
//fix_rcv_window_old

//L.1395
bool DyscoAgentOut::output(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
#ifdef DEBUG
	fprintf(stderr, "[%s][DyscoAgentOut]: receives %s:%u -> %s:%u [%u:%u]\n",
		ns.c_str(),
		printip2(ip->src.value()), tcp->src_port.value(),
		printip2(ip->dst.value()), tcp->dst_port.value(),
		ntohl(tcp->seq_num.value()), ntohl(tcp->ack_num.value()));
#endif
	DyscoHashOut* cb_out = dc->lookup_output(this->index, ip, tcp);
	if(!cb_out) {
		fprintf(stderr, "[%s][DyscoAgentOut] cb_out(lookup_output) is NULL\n", ns.c_str());
		cb_out = dc->lookup_output_pending(this->index, ip, tcp);
		if(cb_out) {
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentOut] cb_out(lookup_output_pending) isn't NULL.\n", ns.c_str());
#endif
			bool retvalue = dc->out_handle_mb(this->index, pkt, ip, tcp, cb_out, devip);		
#ifdef DEBUG
			print_out2(ns, ip, tcp);
#endif	
			return retvalue;
		}

		cb_out = dc->lookup_pending_tag(this->index, tcp);
		if(cb_out) {
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentOut] cb_out(lookup_pending_tag) isn't NULL.\n", ns.c_str());
#endif
			update_five_tuple(ip, tcp, cb_out);
			bool retvalue = dc->out_handle_mb(this->index, pkt, ip, tcp, cb_out, devip);

#ifdef DEBUG
			print_out2(ns, ip, tcp);
#endif
			return retvalue;
		}
	}

	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentOut] It's a TCP SYN segment.\n", ns.c_str());
#endif		
		DyscoHashOut* ret = dc->out_syn(this->index, pkt, ip, tcp, cb_out, devip);
		
#ifdef DEBUG
		print_out2(ns, ip, tcp);
#endif
		if(ret)
			return true;
		
		return false;
	}

	if(!cb_out) {
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentOut] cb_out is NULL.\n", ns.c_str());
#endif
		return false;
	}

	//Ronaldo: is it really necessary?
	//if(cb_out->my_tp && isTCPACK(tcp))
	//	if(!cb_out->state_t)
	//		fix_rcv_window(cb_out);
	//L.1462 -- dysco_output.c ???

	out_translate(pkt, ip, tcp, cb_out);

#ifdef DEBUG
	print_out2(ns, ip, tcp);
#endif	
	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control output
*/

DyscoCbReconfig* DyscoAgentOut::insert_cb_control(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	//Ronaldo:
	//rec_done

	//rcb->super = cmsg->leftSS;
	//TEST //TODO //Ronaldo
	rcb->super = cmsg->super;
	rcb->sub_out.sip = htonl(ip->src.value());
	rcb->sub_out.dip = htonl(ip->dst.value());
	rcb->sub_out.sport = htons(tcp->src_port.value());
	rcb->sub_out.dport = htons(tcp->dst_port.value());
	//rcb->sub_out.sip = ip->src.value();
	//rcb->sub_out.dip = ip->dst.value();
	//rcb->sub_out.sport = dc->allocate_local_port(this->index);
	//rcb->sub_out.dport = dc->allocate_neighbor_port(this->index);
	
	rcb->leftIseq = cmsg->leftIseq;
	rcb->leftIack = cmsg->leftIack;
	rcb->leftIts = cmsg->leftIts;
	rcb->leftItsr = cmsg->leftItsr;
	rcb->leftIws = cmsg->leftIws;
	rcb->leftIwsr = cmsg->leftIwsr;
	rcb->sack_ok = cmsg->sackOk;
	cmsg->sport = rcb->sub_out.sport;
	cmsg->dport = rcb->sub_out.dport;

	if(!dc->insert_hash_reconfig(this->index, rcb))
		return 0;

	fprintf(stderr, "[%s][DyscoAgentOut-Control] Inserting rcb: %p (super: %s)\n",
		ns.c_str(), rcb, print_ss2(rcb->super));
	
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

	//Ronaldo:
	//dysco_arp

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
	//TODO: fix_checksum?

	return true;
}

bool DyscoAgentOut::replace_cb_leftA(DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashOut* old_dcb = rcb->old_dcb;

	if(old_dcb->state == DYSCO_SYN_SENT)
		old_dcb->state = DYSCO_ESTABLISHED;

	cmsg->seqCutoff = htonl(old_dcb->seq_cutoff);
	//TODO: fix_checksum?

	//Ronaldo:
	//rec_done?

	return true;
}

bool DyscoAgentOut::control_output_syn(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);
	
	if(isLeftAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: It's the left anchor.\n", ns.c_str());
#endif
		DyscoHashOut* old_dcb;
		DyscoHashOut* new_dcb;

		if(rcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] It's retransmission. rcb isn't NULL.\n", ns.c_str());
#endif
			cmsg->leftIseq = htonl(rcb->leftIseq);
			cmsg->leftIack = htonl(rcb->leftIack);

			cmsg->leftIts = htonl(rcb->leftIts);
			cmsg->leftItsr = htonl(rcb->leftItsr);

			cmsg->leftIws = htons(rcb->leftIws);
			cmsg->leftIwsr = htonl(rcb->leftIwsr);

			cmsg->sackOk = rcb->sack_ok;
			cmsg->sackOk = htons(cmsg->sackOk);

			cmsg->sport = rcb->sub_out.sport;
			cmsg->dport = rcb->sub_out.dport;

			//fix_checksum

			return true;
		}
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control] rcb is NULL.\n", ns.c_str());
#endif
		//TEST //TODO //Ronaldo
		//old_dcb = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);
		old_dcb = dc->lookup_output_by_ss(this->index, &cmsg->super);

		if(!old_dcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] old_dcb is NULL.\n", ns.c_str());
#endif
			return false;
		}

		cmsg->leftIseq = old_dcb->in_iseq;
		cmsg->leftIack = old_dcb->in_iack;

		cmsg->leftIts = old_dcb->ts_in;
		cmsg->leftItsr = old_dcb->tsr_in;

		cmsg->leftIws = old_dcb->ws_in;
		if(old_dcb->dcb_in)
			cmsg->leftIwsr = old_dcb->dcb_in->ws_in;

		cmsg->sackOk = old_dcb->sack_ok;
		
		rcb = insert_cb_control(ip, tcp, cmsg);
		if(!rcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control] Error to insert_cb_control.\n", ns.c_str());
#endif
			return false;
		}

		new_dcb = new DyscoHashOut();

		rcb->old_dcb = old_dcb;

		new_dcb->sup = rcb->super;
		new_dcb->sub = rcb->sub_out;

		new_dcb->out_iseq = new_dcb->in_iseq = rcb->leftIseq;
		new_dcb->out_iack = new_dcb->in_iack = rcb->leftIack;

		new_dcb->ts_out = new_dcb->ts_in = rcb->leftIts;
		new_dcb->tsr_out = new_dcb->tsr_in = rcb->leftItsr;

		new_dcb->ws_out = new_dcb->ws_in = rcb->leftIws;

		new_dcb->ts_ok = rcb->leftIts? 1 : 0;
		new_dcb->ws_ok = rcb->leftIws? 1 : 0;

		new_dcb->sack_ok = rcb->sack_ok;

		//Ronaldo:
		//dysco_arp

		new_dcb->other_path = old_dcb;
		new_dcb->dcb_in = dc->insert_cb_out_reverse(this->index, new_dcb, 1, cmsg);

		if(!new_dcb->dcb_in) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut-Control]: new_dcb->dcb_in is NULL\n", ns.c_str());
#endif
		} else {
			new_dcb->dcb_in->is_reconfiguration = 1;
		}
		
		memcpy(&new_dcb->cmsg, cmsg, sizeof(DyscoControlMessage));
		new_dcb->is_reconfiguration = 1;

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: new_dcb and new_dcb->dcb_in setted as reconfiguration.\n", ns.c_str());
#endif
		
		old_dcb->old_path = 1;

		if(cmsg->semantic == STATE_TRANSFER)
			old_dcb->state_t = 1;

		//FIXME //TODO //TEST
		//old_dcb->dcb_in->two_paths = 1; //already did in insert_cb_out_reverse
		old_dcb->state = DYSCO_SYN_SENT;

		old_dcb->other_path = new_dcb;

		return true;
	}
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentOut-Control] It isn't the left anchor.\n", ns.c_str());
#endif
	if(rcb && rcb->sub_out.sip != 0)
		return true;

	rcb = insert_cb_control(ip, tcp, cmsg);
	if(!rcb)
		return false;

	control_insert_out(rcb);

	return true;
}
/*
  NOTE: This method uses my_tp.
bool DyscoAgentOut::ctl_save_rcv_window(DyscoControlMessage* cmsg) {

}
*/

bool DyscoAgentOut::control_output(Ipv4* ip, Tcp* tcp) {
	//DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg;

	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + (tcp->offset << 2);
	cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s][DyscoAgentOut-Control]: control_output method\n", ns.c_str());
#endif

	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: It's a SYN message.\n", ns.c_str());
#endif
		return control_output_syn(ip, tcp, cmsg);
	}

	/*
	  ------------------Never reach here, because DyscoAgentIn will handle SYN/ACK and ACK reconfiguration packet.
	  else if(isTCPSYN(tcp) && isTCPACK(tcp)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: It's a SYN/ACK message.\n", ns.c_str());
#endif
		if(isRightAnchor(ip, cmsg))
			replace_cb_rightA(cmsg);
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: It's an ACK message.\n", ns.c_str());
#endif
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);
		if(!rcb)
			return false;
		
		if(ntohs(cmsg->semantic) == STATE_TRANSFER)
			return true;
		
		if(isLeftAnchor(ip, cmsg))
			if(!rcb->old_dcb->state_t)
				replace_cb_leftA(rcb, cmsg);
	} else {
#ifdef DYSCO_RECONFIG
		fprintf(stderr, "[%s][DyscoAgentOut-Control]: It isn't a SYN, SYN/ACK or ACK message.\n", ns.c_str());
#endif
}*/
	
	return true;
}

/*

 */
void DyscoAgentOut::process_arp(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	bess::utils::Arp* arp = reinterpret_cast<bess::utils::Arp*>(eth + 1);

	if(arp->opcode.value() == bess::utils::Arp::kRequest ||
	   arp->opcode.value() == bess::utils::Arp::kReply) {
		dc->update_mac(arp->sender_hw_addr, arp->sender_ip_addr);
	}
}

void DyscoAgentOut::process_ethernet(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	
	char* dst_ether = dc->get_mac(ip->dst);
	if(!dst_ether) {
#ifdef DEBUG
		fprintf(stderr, "[DyscoAgentOut]: get_mac returns NULL\n");
#endif
		return;
	}

	for(int i = 0; i < 6; i++) {
		eth->dst_addr.bytes[i] = dst_ether[i];
	}

#ifdef DEBUG
	fprintf(stderr, "[DyscoAgentOut]: DST MAC changed to ");
	for(int i = 0; i < 5; i++)
		fprintf(stderr, "%X:", dst_ether[i]);
	fprintf(stderr, "%X.\n", dst_ether[5]);
#endif
}

void DyscoAgentOut::dysco_packet(Ethernet* eth) {
	eth->dst_addr.FromString(DYSCO_MAC);
}

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming from host")






