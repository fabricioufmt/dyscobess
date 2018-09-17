#include <netinet/tcp.h>

#include "dysco_port_out.h"
#include "dysco_agent_in.h"

uint64_t DyscoAgentIn::timeout;

const Commands DyscoAgentIn::cmds = {
	{"setup", "EmptyArg", MODULE_CMD_FUNC(&DyscoAgentIn::CommandSetup), Command::THREAD_UNSAFE}
};

void timer_worker(DyscoAgentIn* agent) {
	while(1) {
		usleep(SLEEPTIME);
		agent->retransmissionHandler();
	}
}

DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
	timeout = DEFAULT_TIMEOUT;
	timer = new thread(timer_worker, this);
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

CommandResponse DyscoAgentIn::CommandSetup(const bess::pb::EmptyArg&) {
	if(setup())
		return CommandSuccess();
	
	return CommandFailure(EINVAL, "ERROR: Port information.");
}

void DyscoAgentIn::ProcessBatch(PacketBatch* batch) {
	if(!dc) {
		RunChooseModule(0, batch);
		return;
	}
	
	PacketBatch out_gates[2];
	out_gates[0].clear();
	out_gates[1].clear();

	Tcp* tcp;
	Ipv4* ip;
	Packet* pkt;
	Ethernet* eth;
	size_t ip_hlen;
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;
	DyscoTcpOption* tcpo;
	DyscoControlMessage* cmsg;
	
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		
		eth = pkt->head_data<Ethernet*>();
		if(!isIP(eth)) {
			out_gates[0].add(pkt);
			continue;
		}

		ip = reinterpret_cast<Ipv4*>(eth + 1);
		if(!isTCP(ip)) {
			out_gates[0].add(pkt);
			continue;
		}
		
		ip_hlen = ip->header_length << 2;
		tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentIn] receives %s [%X:%X]\n", ns.c_str(), printPacketSS(ip, tcp),	tcp->seq_num.value(), tcp->ack_num.value());
#endif

		cb_in = dc->lookup_input(this->index, ip, tcp);

		if(isLockingSignalPacket(tcp)) {
#ifdef DEBUG
			fprintf(stderr, "Receives Locking Signal Packet.\n");
#endif
			if(processLockingSignalPacket(pkt, eth, ip, tcp, cb_in)) {
				out_gates[1].add(pkt);
				continue;
			}
			
		} else if(isLockingPacket(ip, tcp)) {
#ifdef DEBUG
			fprintf(stderr, "Receives Locking Packet.\n");
#endif

			switch(processLockingPacket(pkt, eth, ip, tcp)) {
			case TO_GATE_1:
				out_gates[1].add(pkt);
				break;
			case LOCK_SUCCESSFUL:
				//out_gates[1].add(createAckLock(pkt, ip, tcp));
				startReconfiguration(pkt, eth, ip, tcp);
				break;
			case ERROR:
			default:
				break;
			}
			
		} else if(isReconfigPacket(ip, tcp, cb_in)) {
#ifdef DEBUG
			fprintf(stderr, "It is reconfig packet\n");
#endif
			switch(control_input(pkt, ip, tcp, cb_in)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwards %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				break;
				
			case TO_GATE_1:
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentIn-Control] forwarding to toRetransmit %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.value(), tcp->ack_num.value());
#endif
				dc->add_retransmission(this->index, devip, pkt);
				break;

			case IS_RETRANSMISSION:
				//out_gates[1].add(pkt);
				break;
				
			case END:
#ifdef DEBUG
				fprintf(stderr, "3-way from Reconfiguration Session is DONE.\n\n");
				fprintf(stderr, "cb_in->dcb_out->other_path: %s %s\n", printSS(cb_in->dcb_out->other_path->sub), printSS(cb_in->dcb_out->other_path->sup));
#endif
				break;
				
			case ERROR:
#ifdef DEBUG
				fprintf(stderr, "ERROR on control_input\n");
#endif
			default:
				break;
			}

		} else {
#ifdef DEBUG
			fprintf(stderr, "It isn't reconfig packet\n");
#endif
			switch(input(pkt, ip, tcp, cb_in)) {
			case TO_GATE_0:
				out_gates[0].add(pkt);
				break;
				
			case TO_GATE_1:
				out_gates[1].add(pkt);
				break;
				
			default:
				break;
			}
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.value(), tcp->ack_num.value());
#endif
		}
	}
	
	batch->clear();
	RunChooseModule(0, &(out_gates[0]));
	RunChooseModule(1, &(out_gates[1]));
}

bool DyscoAgentIn::isReconfigPacket(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	bool removed_from_retransmission = processReceivedPacket(tcp);

	if(ip->dst.raw_value() != devip)
		return false;

	uint32_t payload_len = hasPayload(ip, tcp);
	
	if(isTCPSYN(tcp, true)) {
		if(!cb_in) {
			if(payload_len) {
				uint32_t tcp_hlen = tcp->offset << 2;
				/*
				if(((uint8_t*)tcp + tcp_hlen)[payload_len - 1] == 0xFF)
					return true;
				*/
				DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(((uint8_t*)tcp) + tcp_hlen);
				if(!cmsg)
					return false;
				
				return cmsg->type == DYSCO_RECONFIG;
			}

			return false;
		}

		if(cb_in->dcb_out == 0) {
#ifdef DEBUG
			fprintf(stderr, "isReconfigPacket: cb_in->dcb_out is NULL\n");
#endif
			return false;
		}

		if(cb_in->dcb_out->state == DYSCO_SYN_RECEIVED && payload_len > 0) {
#ifdef DEBUG
			fprintf(stderr, "isReconfigPacket: SYN_RECEIVED and hasPayload == TRUE\n");
#endif
			return true;
		}
#ifdef DEBUG
		fprintf(stderr, "isReconfigPacket: FALSE\n");
#endif
		
		return false;
	}

	if(!cb_in)
		return false;

	if(isTCPSYN(tcp) && isTCPACK(tcp)) {
		if(cb_in->is_reconfiguration) {
#ifdef DEBUG
			fprintf(stderr, "is SYN+ACK reconfiguration Packet.\n");
#endif
			return true;
		}

		if(cb_in->dcb_out->other_path && cb_in->dcb_out->other_path->state == DYSCO_ESTABLISHED)
			return true;

		return false;
	}

	if(isTCPACK(tcp, true)) {
		if(cb_in->is_reconfiguration) {
			return true;
		}

		if(cb_in->dcb_out->other_path && cb_in->dcb_out->other_path->state == DYSCO_ESTABLISHED) {
			if(removed_from_retransmission)
				return true;
			
			return false;
		}
	}

	return false;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below.
*/
void DyscoAgentIn::remove_sc(Packet* pkt, Ipv4* ip, uint32_t payload_sz) {
	pkt->trim(payload_sz);
	ip->length = ip->length - be16_t(payload_sz);
}

//L.327
uint32_t DyscoAgentIn::in_rewrite_seq(Tcp* tcp, DyscoHashIn* cb_in) {
	if(cb_in->seq_delta) {
		uint32_t new_seq;
		uint32_t seq = tcp->seq_num.value();

		if(cb_in->seq_add)
			new_seq = seq + cb_in->seq_delta;
		else
			new_seq = seq - cb_in->seq_delta;

		tcp->seq_num = be32_t(new_seq);
		
		return ChecksumIncrement32(htonl(seq), htonl(new_seq));
	}

	return 0;
}

//L.355
uint32_t DyscoAgentIn::in_rewrite_ack(Tcp* tcp, DyscoHashIn* cb_in) {
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

		return ChecksumIncrement32(htonl(ack), htonl(new_ack));
	}
	
	return 0;
}

//L.384
uint32_t DyscoAgentIn::in_rewrite_ts(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in->ts_ok)
		return 0;
	
	DyscoTcpTs* ts = get_ts_option(tcp);
	if(!ts)
		return 0;

	uint32_t incremental = 0;
	uint32_t new_ts, new_tsr;
	
	if(cb_in->ts_delta) {
		if(cb_in->ts_add)
			new_ts = ntohl(ts->ts) + cb_in->ts_delta;
		else
			new_ts = ntohl(ts->ts) - cb_in->ts_delta;

		new_ts = htonl(new_ts);
		incremental += ChecksumIncrement32(ts->ts, new_ts);
		ts->ts = new_ts;
	}

	if(cb_in->tsr_delta) {
		if(cb_in->tsr_add)
			new_tsr = ntohl(ts->tsr) + cb_in->tsr_delta;
		else
			new_tsr = ntohl(ts->tsr) - cb_in->tsr_delta;

		new_tsr = htonl(new_tsr);
		incremental += ChecksumIncrement32(ts->tsr, new_tsr);
		ts->tsr = new_tsr;
	}
		
	return incremental;
}

//L.432
uint32_t DyscoAgentIn::in_rewrite_rcv_wnd(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in->ws_ok)
		return 0;
	
	if(cb_in->ws_delta) {
		uint16_t new_win;
		uint32_t wnd = tcp->window.value();

		wnd <<= cb_in->ws_in;
		wnd >>= cb_in->ws_out;
		new_win = htons(wnd);
		new_win = ntohs(new_win);
		tcp->window = be16_t(new_win);

		return ChecksumIncrement16(htons(wnd), htons(new_win));
	}

	return 0;
}

//L.458
void DyscoAgentIn::in_hdr_rewrite_csum(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	hdr_rewrite_csum(ip, tcp, &cb_in->my_sup);
	
	uint32_t incremental = 0;

	incremental += in_rewrite_seq(tcp, cb_in);
	incremental += in_rewrite_ack(tcp, cb_in);
	incremental += in_rewrite_ts(tcp, cb_in);
	incremental += in_rewrite_rcv_wnd(tcp, cb_in);
	
	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
}

//L.505
bool DyscoAgentIn::rx_initiation_new(Packet* pkt, Ipv4* ip, Tcp* tcp, uint32_t payload_sz) {
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + (tcp->offset << 2);

	DyscoHashIn* cb_in = new DyscoHashIn();
	cb_in->module = this;
	cb_in->sub.sip = ip->src.raw_value();
	cb_in->sub.dip = ip->dst.raw_value();
	cb_in->sub.sport = tcp->src_port.raw_value();
	cb_in->sub.dport = tcp->dst_port.raw_value();

	memcpy(&cb_in->mac_sub, pkt->head_data<Ethernet*>(), sizeof(Ethernet));

	DyscoTcpSession* neigh_supss = reinterpret_cast<DyscoTcpSession*>(payload);
	DyscoTcpSession* neigh_subss = reinterpret_cast<DyscoTcpSession*>(payload + sizeof(DyscoTcpSession));

	cb_in->neigh_sup.sip = neigh_supss->sip;
	cb_in->neigh_sup.dip = neigh_supss->dip;
	cb_in->neigh_sup.sport = neigh_supss->sport;
	cb_in->neigh_sup.dport = neigh_supss->dport;
	
	if(neigh_subss->sip != cb_in->sub.sip || neigh_subss->sport != cb_in->sub.sport) {
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentIn] NAT crossed.\n", ns.c_str());
#endif
		cb_in->my_sup = cb_in->sub;
		cb_in->my_sup.dip = neigh_supss->dip;
		cb_in->my_sup.dport = neigh_supss->dport;
	} else {
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentIn] not NAT crossed.\n", ns.c_str());
#endif
		cb_in->my_sup.sip = neigh_supss->sip;
		cb_in->my_sup.dip = neigh_supss->dip;
		cb_in->my_sup.sport = neigh_supss->sport;
		cb_in->my_sup.dport = neigh_supss->dport;
	}

	if(payload_sz > 2 * sizeof(DyscoTcpSession) + sizeof(uint32_t)) {
#ifdef DEBUG
		fprintf(stderr, "I am not last one on service chain.\n");
#endif
		uint32_t sc_len = (payload_sz - 2 * sizeof(DyscoTcpSession))/sizeof(uint32_t);

		DyscoHashOut* cb_out = new DyscoHashOut();

		/*
		cb_out->sup.sip = neigh_supss->sip;
		cb_out->sup.dip = neigh_supss->dip;
		cb_out->sup.sport = neigh_supss->sport;
		cb_out->sup.dport = neigh_supss->dport;
		*/

		cb_out->sup = cb_in->my_sup;
		
		cb_out->dysco_tag = dc->get_dysco_tag(this->index);
		cb_out->sc_len = sc_len - 1;
		cb_out->sc = new uint32_t[sc_len - 1];
		memcpy(cb_out->sc, payload + 2 * sizeof(DyscoTcpSession) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
		
		if(!dc->insert_pending(this->index, cb_out)) {
			dc->remove_hash_input(this->index, cb_in);
			delete cb_in;
			dc->remove_hash_output(this->index, cb_out);
			delete cb_out;
			
			return false;
		}
	}
	
	if(!dc->insert_hash_input(this->index, cb_in)) {
		dc->remove_hash_input(this->index, cb_in);
		delete cb_in;

		return false;
	}

	cb_in->dcb_out = insert_cb_in_reverse(cb_in, ip, tcp);
	
	cb_in->in_iseq = tcp->seq_num.value();
	cb_in->in_iack = tcp->ack_num.value();

	remove_sc(pkt, ip, payload_sz);
	parse_tcp_syn_opt_r(tcp, cb_in);
	insert_tag(pkt, ip, tcp);
	hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);
	
	return true;
}

DyscoHashOut* DyscoAgentIn::insert_cb_in_reverse(DyscoHashIn* cb_in, Ipv4* ip, Tcp* tcp) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	
	cb_out->sup.sip = cb_in->my_sup.dip;
	cb_out->sup.dip = cb_in->my_sup.sip;
	cb_out->sup.sport = cb_in->my_sup.dport;
	cb_out->sup.dport = cb_in->my_sup.sport;

	if(!(cb_in->neigh_sup == cb_in->my_sup)) {
#ifdef DEBUG
		fprintf(stderr, "NAT crossed -- inserting a fake cb_out with neigh_sup\n");
#endif

		DyscoHashOut* cb_out_nat = new DyscoHashOut();

		cb_out_nat->sup.sip = cb_in->neigh_sup.dip;
		cb_out_nat->sup.dip = cb_in->neigh_sup.sip;
		cb_out_nat->sup.sport = cb_in->neigh_sup.dport;
		cb_out_nat->sup.dport = cb_in->neigh_sup.sport;

		cb_out_nat->is_nat = true;
		cb_out_nat->other_path = cb_out;

		dc->insert_hash_output(this->index, cb_out_nat);
	}
	
	cb_out->sub.sip = ip->dst.raw_value();
	cb_out->sub.dip = ip->src.raw_value();
	cb_out->sub.sport = tcp->dst_port.raw_value();
	cb_out->sub.dport = tcp->src_port.raw_value();

	cb_out->mac_sub.src_addr = cb_in->mac_sub.dst_addr;
	cb_out->mac_sub.dst_addr = cb_in->mac_sub.src_addr;
	
	cb_out->in_iack = tcp->seq_num.value();
	cb_out->out_iack = tcp->seq_num.value();

	cb_out->other_path = 0;
	cb_out->old_path = 0;
	cb_out->valid_ack_cut = 0;
	cb_out->use_np_seq = 0;
	cb_out->use_np_ack = 0;
	cb_out->ack_cutoff = 0;

	cb_out->ack_ctr = 0;
	cb_out->state = DYSCO_ONE_PATH;

	cb_out->dcb_in = cb_in;

	dc->insert_hash_output(this->index, cb_out);
	
	return cb_out;
}

//L.614
bool DyscoAgentIn::in_two_paths_ack(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out) {
		return false;
	}
	/*
	if(cb_out->old_path) {
		if(!cb_out->state_t) {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out) {
			return false;
		}

		if(!cb_out->state_t) {
			if(!dc->after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				//cb_in->two_paths = 0;
				
			}
		}
	}
	*/

	if(cb_out->old_path) {
		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
		} else {
			if(!after(cb_out->seq_cutoff, ack_seq)) {
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
			if(!after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
				
			}
		}
	}

	return true;
}

//L.683
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in, uint32_t payload) {
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
				if(before(seq, old_out->ack_cutoff)) {
#ifdef DEBUG
					fprintf(stderr, "setting onto %s %s ack_cutoff: %X.\n", printSS(old_out->sup), printSS(old_out->sub), seq);
#endif
					old_out->ack_cutoff = seq;
				}
			} else {
#ifdef DEBUG
				fprintf(stderr, "setting onto %s %s ack_cutoff: %X.\n", printSS(old_out->sup), printSS(old_out->sub), seq);
#endif
				old_out->ack_cutoff = seq;
				old_out->valid_ack_cut = 1;
			}
		}
	} else {
		//TEST
		uint32_t seq = tcp->seq_num.value() + payload + 1;
#ifdef DEBUG
		fprintf(stderr, "setting onto %s %s ack_cutoff: %X.\n", printSS(cb_out->sup), printSS(cb_out->sub), seq);
#endif
		cb_out->ack_cutoff = seq;	
	}

	return true;
}

//L.753
CONTROL_RETURN DyscoAgentIn::input(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t payload_sz = hasPayload(ip, tcp);
	
	if(!cb_in) {
		if(isTCPSYN(tcp, true) && payload_sz)
			rx_initiation_new(pkt, ip, tcp, payload_sz);
		
		return TO_GATE_0;
	}

	if(isTCPACK(tcp, true)) {
		if(cb_in->dcb_out->old_path && cb_in->dcb_out->state == DYSCO_LAST_ACK) {
			cb_in->dcb_out->state = DYSCO_CLOSED;

			return ERROR;
		} else if(cb_in->dcb_out->state == DYSCO_SYN_RECEIVED)
			cb_in->dcb_out->state = DYSCO_ESTABLISHED;

		else if(cb_in->dcb_out->state == DYSCO_FIN_WAIT_1)
			cb_in->dcb_out->state = DYSCO_FIN_WAIT_2;

		else if(cb_in->dcb_out->state == DYSCO_CLOSING)
			cb_in->dcb_out->state = DYSCO_CLOSED;
	}
	
	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp)) {
			set_ack_number_out(tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			if(cb_in->dcb_out->state == DYSCO_SYN_SENT)
				cb_in->dcb_out->state = DYSCO_ESTABLISHED;
		} else {
			//It is retransmission packet
			//just remove sc (if there is) and insert Dysco Tag
			if(payload_sz) {
				remove_sc(pkt, ip, payload_sz);
				insert_tag(pkt, ip, tcp);
				hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);
			}
		}
		
		return TO_GATE_0;
	}

	if(isTCPFIN(tcp)) {
		if(cb_in->dcb_out->old_path && cb_in->dcb_out->other_path->state == DYSCO_ESTABLISHED) {
			createFinAck(pkt, ip, tcp);
			cb_in->dcb_out->state = DYSCO_LAST_ACK;

			return TO_GATE_1;
		}
	}

	if(cb_in->two_paths) {
		if(!payload_sz)
			in_two_paths_ack(tcp, cb_in);
		else if(!in_two_paths_data_seg(tcp, cb_in, payload_sz))
			return TO_GATE_0;
			
	}
	
	in_hdr_rewrite_csum(ip, tcp, cb_in);

	return TO_GATE_0;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control input
*/

DyscoCbReconfig* DyscoAgentIn::insert_rcb_control_input(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();
	
	rcb->super = cmsg->rightSS;
	rcb->leftSS = cmsg->leftSS;
	rcb->rightSS = cmsg->rightSS;
	rcb->sub_in.sip = ip->src.raw_value();
	rcb->sub_in.dip = ip->dst.raw_value();
	rcb->sub_in.sport = tcp->src_port.raw_value();
	rcb->sub_in.dport = tcp->dst_port.raw_value();
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

#ifdef DEBUG
	fprintf(stderr, "Inserting %s in hash_reconfig.\n", printSS(rcb->super));
#endif
	
	return rcb;
}

DyscoHashOut* DyscoAgentIn::build_cb_in_reverse(Ipv4*, DyscoCbReconfig* rcb) {
	DyscoHashOut* cb_out = new DyscoHashOut();

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
	
	if(cb_in->in_iseq < cb_in->out_iseq) {
		cb_in->seq_delta = cb_in->out_iseq - cb_in->in_iseq;
		cb_in->seq_add = 1;
	} else {
		cb_in->seq_delta = cb_in->in_iseq - cb_in->out_iseq;
		cb_in->seq_add = 0;
	}
	
	if(cb_in->in_iack < cb_in->out_iack) {
		cb_in->ack_delta = cb_in->out_iack - cb_in->in_iack;
		cb_in->ack_add = 1;
	} else {
		cb_in->ack_delta = cb_in->in_iack - cb_in->out_iack;
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
	
	if(cb_out->in_iseq < cb_out->out_iseq) {
		cb_out->seq_delta = cb_out->out_iseq - cb_out->in_iseq;
		cb_out->seq_add = 1;
	} else {
		cb_out->seq_delta = cb_out->in_iseq - cb_out->out_iseq;
		cb_out->seq_add = 0;
	}

	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
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

#ifdef DEBUG	
	fprintf(stderr, "Looking for %s in hash_output... \n", printSS(local_ss));
#endif

	cb_in->my_sup = cmsg->rightSS;
	
	DyscoHashOut* old_out = dc->lookup_output_by_ss(this->index, &local_ss);
	if(!old_out) {
#ifdef DEBUG
		fprintf(stderr, "Not found\n");
#endif
		dc->remove_hash_input(this->index, cb_in);
		delete cb_in;
		dc->remove_hash_reconfig(this->index, rcb);
		delete rcb;

		return false;
	} else {
#ifdef DEBUG
		fprintf(stderr, "Found\n");
#endif
		if(old_out->is_nat) {
#ifdef DEBUG
			fprintf(stderr, "is NAT and switching cb_outs\n");
#endif
			old_out = old_out->other_path;
			cb_in->my_sup.sip = old_out->sup.dip;
			cb_in->my_sup.dip = old_out->sup.sip;
			cb_in->my_sup.sport = old_out->sup.dport;
			cb_in->my_sup.dport = old_out->sup.sport;
			cb_in->neigh_sup = cmsg->rightSS;
		}
	}

	compute_deltas_in(cb_in, old_out, rcb);
	compute_deltas_out(cb_out, old_out, rcb);

	cb_in->two_paths = 1;

	rcb->new_dcb = cb_out;
	rcb->old_dcb = old_out;
	cb_out->other_path = old_out;
	
	if(ntohl(cmsg->semantic) == STATE_TRANSFER)
		old_out->state_t = 1;
	
	return true;
}

void DyscoAgentIn::insert_tag(Packet* pkt, Ipv4* ip, Tcp* tcp) {
	uint32_t tag = dc->get_dysco_tag(index);
	DyscoTcpOption* dopt = reinterpret_cast<DyscoTcpOption*>(pkt->append(DYSCO_TCP_OPTION_LEN));
	
	dopt->kind = DYSCO_TCP_OPTION;
	dopt->len = DYSCO_TCP_OPTION_LEN;
	dopt->padding = 0;
	dopt->tag = tag;

	tcp->offset += (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length + be16_t(DYSCO_TCP_OPTION_LEN);
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
		cb_in->module = this;
		cb_in->sub = rcb->sub_in;
		cb_in->out_iseq = rcb->leftIseq;
		cb_in->out_iack = rcb->leftIack;
		cb_in->seq_delta = cb_in->ack_delta = 0;

		cb_in->in_iseq = tcp->seq_num.value();
		cb_in->in_iack = tcp->ack_num.value();;
				
		cb_in->is_reconfiguration = 1;
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
		cb_out = build_cb_in_reverse(ip, rcb);

		if(!cb_out) {
			dc->remove_hash_input(this->index, cb_in);
			delete cb_in;
			dc->remove_hash_reconfig(this->index, rcb);
			delete rcb;
			
			return ERROR;
		}

		cb_in->dcb_out = cb_out;
		cb_out->dcb_in = cb_in;
		
		dc->insert_hash_input(this->index, cb_in);
		
		createSynAck(pkt, ip, tcp, cb_out->out_iseq);
		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out)) {
#ifdef DEBUG
			fprintf(stderr, "control_config_rightA returns false\n");
#endif
			return ERROR;
		}
		
		//replace_cb_rightA method from control_output
		DyscoHashOut* old_out = rcb->old_dcb;
		DyscoHashOut* new_out = rcb->new_dcb;
		uint32_t seq_cutoff = old_out->seq_cutoff;

		old_out->old_path = 1;
		old_out->other_path = new_out;
		
		if(new_out->seq_add)
			seq_cutoff += new_out->seq_delta;
		else
			seq_cutoff -= new_out->seq_delta;

		new_out->state = DYSCO_SYN_RECEIVED;
		
		return TO_GATE_1;
	}

#ifdef DEBUG
	fprintf(stderr, "It isn't the right anchor.\n");
#endif

	cb_in = new DyscoHashIn();
	cb_in->module = this;
	cb_in->sub.sip = ip->src.raw_value();
	cb_in->sub.dip = ip->dst.raw_value();
	cb_in->sub.sport = tcp->src_port.raw_value();
	cb_in->sub.dport = tcp->dst_port.raw_value();

	DyscoTcpSession* neigh_supss = &cmsg->super;
	cb_in->neigh_sup.sip = neigh_supss->sip;
	cb_in->neigh_sup.dip = neigh_supss->dip;
	cb_in->neigh_sup.sport = neigh_supss->sport;
	cb_in->neigh_sup.dport = neigh_supss->dport;

	DyscoTcpSession* leftSS = &cmsg->leftSS;
	cb_in->my_sup.sip = leftSS->sip;
	cb_in->my_sup.dip = leftSS->dip;
	cb_in->my_sup.sport = leftSS->sport;
	cb_in->my_sup.dport = leftSS->dport;
	
	uint32_t sc_len = (payload_sz - sizeof(DyscoControlMessage))/sizeof(uint32_t);
	
	if(sc_len > 1) {
#ifdef DEBUG
		fprintf(stderr, "I am not last one on service chain.\n");
#endif	
		cb_out = new DyscoHashOut();

		cb_out->sup = cb_in->my_sup;
		
		cb_out->dysco_tag = dc->get_dysco_tag(this->index);
		cb_out->sc_len = sc_len - 1;
		cb_out->sc = new uint32_t[sc_len - 1];
		memcpy(cb_out->sc, payload + sizeof(DyscoControlMessage) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
		cb_out->is_reconfiguration = 1;
		memcpy(&cb_out->cmsg, cmsg, sizeof(DyscoControlMessage));
		
		if(!dc->insert_pending_reconfig(this->index, cb_out)) {
			dc->remove_hash_input(this->index, cb_in);
			delete cb_in;
			dc->remove_hash_output(this->index, cb_out);
			delete cb_out;

			return ERROR;
		}
	}

	if(!dc->insert_hash_input(this->index, cb_in)) {
		dc->remove_hash_input(this->index, cb_in);
		delete cb_in;

		return ERROR;
	}
	
	cb_in->dcb_out = insert_cb_in_reverse(cb_in, ip, tcp);
	
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

	//uint32_t* sc = (uint32_t*)(payload + sizeof(DyscoControlMessage));
		
	if(ntohs(cmsg->semantic) == NOSTATE_TRANSFER || sc_len < 2) {
		remove_sc(pkt, ip, payload_sz);
		insert_tag(pkt, ip, tcp);
		hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);
	
		return TO_GATE_0;
	}

	return TO_GATE_1;
}




bool DyscoAgentIn::set_ack_number_out(Tcp* tcp, DyscoHashIn* cb_in) {
	cb_in->in_iseq = cb_in->out_iseq = tcp->seq_num.value();
	cb_in->in_iack = cb_in->out_iack = tcp->ack_num.value() - 1;
	cb_in->seq_delta = cb_in->ack_delta = 0;

	DyscoTcpSession ss;
	ss.sip = cb_in->my_sup.dip;
	ss.dip = cb_in->my_sup.sip;
	ss.sport = cb_in->my_sup.dport;
	ss.dport = cb_in->my_sup.sport;

	DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &ss);

	if(!cb_out)
		return false;

	cb_out->out_iack = cb_out->in_iack = tcp->seq_num.value();
	cb_out->out_iseq = cb_out->in_iseq = tcp->ack_num.value() - 1;
	
	parse_tcp_syn_opt_r(tcp, cb_in);
	if(cb_in->ts_ok) {
		cb_out->ts_ok = 1;
		cb_out->tsr_out = cb_out->tsr_in = cb_in->ts_in;
		cb_out->ts_out = cb_out->ts_in = cb_in->tsr_in;

		cb_out->ts_delta = cb_out->tsr_delta = 0;
	}

	if(!cb_in->sack_ok)
		cb_out->sack_ok = 0;

	return true;
}

CONTROL_RETURN DyscoAgentIn::control_input(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg = 0;
	size_t tcp_hlen = tcp->offset << 2;

	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG
		fprintf(stderr, "DYSCO_SYN message.\n");
#endif

		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		cmsg = reinterpret_cast<DyscoControlMessage*>(payload);

		//Ronaldo: RightA doesn't know about supss (or leftSS)
		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->rightSS); 
		if(rcb) {
#ifdef DEBUG
			fprintf(stderr, "It's retransmission of SYN.\n\n");
#endif
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
			
			DyscoHashOut* cb_out = cb_in->dcb_out;
			if(!cb_out) {
				return ERROR;
			}

			if(cb_out->state == DYSCO_ESTABLISHED) {
#ifdef DEBUG
				fprintf(stderr, "Is a retransmission packet (already ESTABLISHED state)\n");
#endif
				createAck(pkt, ip, tcp);
				
				return IS_RETRANSMISSION;
			}
			
			createAck(pkt, ip, tcp);
			
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_out->sup);
			if(!rcb) {
				return ERROR;
			}

			if(!rcb->old_dcb) {
				return ERROR;
			}
			
			DyscoHashOut* old_dcb = rcb->old_dcb;

			if(!old_dcb->valid_ack_cut) {
				old_dcb->valid_ack_cut = 1;
				old_dcb->use_np_ack = 1;
			}
			
			cb_out->state = DYSCO_ESTABLISHED;

			cb_in->is_reconfiguration = 0;
			
			if(!rcb->old_dcb->state_t) {
				if(!old_dcb) {
					return ERROR;
				}
			}
			
			return TO_GATE_1;
		} else {
#ifdef DEBUG
			fprintf(stderr, "It isn't left anchor.\n");
#endif		
			set_ack_number_out(tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			return TO_GATE_0;
		}
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG
		fprintf(stderr, "DYSCO_ACK message.\n");
#endif

		if(!cb_in) {
#ifdef DEBUG
			fprintf(stderr, "cb_in ERROR\n");
#endif
			return ERROR;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
#ifdef DEBUG
			fprintf(stderr, "cmsg ERROR\n");
#endif
			return ERROR;
		}
		
		if(isToRightAnchor(ip, cmsg)) {
#ifdef DEBUG
			fprintf(stderr, "It's the right anchor.\n");
#endif
			
#ifdef DEBUG
			fprintf(stderr, "Looking for %s in hash_reconfig.\n", printSS(cb_in->my_sup));
			fprintf(stderr, "Or should be neigh_sup: %s ?.\n", printSS(cb_in->neigh_sup));
#endif
			
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->my_sup);
			if(!rcb) {
#ifdef DEBUG
				fprintf(stderr, "Looking for %s on hash_reconfig, NOT FOUND.\n", printSS(cb_in->my_sup));
#endif
				rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->neigh_sup);
				if(!rcb) {
#ifdef DEBUG
					fprintf(stderr, "Looking for %s on hash_reconfig, NOT FOUND.\n", printSS(cb_in->neigh_sup));
#endif
					return ERROR;
				}
			}
			
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

			old_out_ack_cutoff = cb_in->in_iseq;
			
			if(new_out->in_iack < new_out->out_iack) {
				uint32_t delta = new_out->out_iack - new_out->in_iack;
				old_out_ack_cutoff += delta;
			}

			if(new_out->state == DYSCO_SYN_RECEIVED)
				new_out->state = DYSCO_ESTABLISHED;
			
			if(!old_out->state_t) {
#ifdef DEBUG
				fprintf(stderr, "setting onto %s %s to ack_cutoff: %x.\n", printSS(old_out->sup), printSS(old_out->sub), old_out_ack_cutoff);
#endif
				old_out->ack_cutoff = old_out_ack_cutoff;
				old_out->valid_ack_cut = 1;
			}

			return END;
		}
#ifdef DEBUG
		fprintf(stderr, "It isn't the right anchor.\n");
#endif
		set_ack_number_out(tcp, cb_in);
		in_hdr_rewrite_csum(ip, tcp, cb_in);
		
		return TO_GATE_0;
	}

	//STATE_TRANSFER -- not tested
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

/*
  Auxiliary methods
 */
bool DyscoAgentIn::setup() {
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

void DyscoAgentIn::createAck(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
		
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);
	
	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;

	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = be32_t(tcp->ack_num.value());
	tcp->ack_num = be32_t(seqswap.value() + 1);
	tcp->flags = Tcp::kAck;

	//Could be incremental
	fix_csum(ip, tcp);
}

void DyscoAgentIn::createSynAck(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, uint32_t) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
		
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);
	uint32_t payload_len = hasPayload(ip, tcp);
	ip->length = ip->length - be16_t(payload_len);

	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;
	
	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = tcp->ack_num;
	//tcp->seq_num = be32_t(ISN);
	//tcp->ack_num = seqswap + be32_t(1) + be32_t(payload_len);
	tcp->ack_num = seqswap + be32_t(1);
	tcp->flags |= Tcp::kAck;
	pkt->trim(payload_len);

	fix_csum(ip, tcp);
}

void DyscoAgentIn::createFinAck(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
		
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);

	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;
	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = seqswap + be32_t(1);
	tcp->flags |= Tcp::kAck;

	//Could be incremental
	fix_csum(ip, tcp);
}

/*
  - remove TCP Option
  - increase Packet buffer (sizeof(DyscoControlMessage))
 */
void DyscoAgentIn::createLockingPacket(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoTcpOption* tcpo, DyscoHashIn* cb_in) {
#ifdef DEBUG
	fprintf(stderr, "creating Locking Packet\n");
#endif
	
	uint8_t rhop = tcpo->padding & 0xff;
	
	pkt->trim(tcpo->len + hasPayload(ip, tcp));
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(pkt->append(sizeof(DyscoControlMessage)));

	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;
	
	ip->id = be16_t(rand());
	ip->ttl = 53;
	ip->checksum = 0;

	be32_t ipswap = ip->src;
	ip->src = ip->dst;
	ip->dst = ipswap;
	
	ip->length = be16_t(ip->length.value() - tcpo->len - hasPayload(ip, tcp) + sizeof(DyscoControlMessage));
	memset(cmsg, 0, sizeof(DyscoControlMessage));

	tcp->src_port = be16_t(rand());
	tcp->dst_port = be16_t(rand());
	tcp->seq_num = be32_t(rand());
	tcp->ack_num = be32_t(0);
	tcp->offset = 5;
	tcp->flags = Tcp::kSyn;

	cb_in->dcb_out->is_LA = 1;
	cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;
	
	cmsg->type = DYSCO_LOCK;
	cmsg->lock_state = DYSCO_REQUEST_LOCK;
	cmsg->leftA = ip->src.raw_value();
	cmsg->my_sub.sip = cb_in->sub.dip;
	cmsg->my_sub.dip = cb_in->sub.sip;
	cmsg->my_sub.sport = cb_in->sub.dport;
	cmsg->my_sub.dport = cb_in->sub.sport;
	cmsg->super.sip = cb_in->my_sup.dip;
	cmsg->super.dip = cb_in->my_sup.sip;
	cmsg->super.sport = cb_in->my_sup.dport;
	cmsg->super.dport = cb_in->my_sup.sport;
	cmsg->lhop = rhop;
	cmsg->rhop = rhop;

#ifdef DEBUG
	fprintf(stderr, "cb_in->sub: %s\n", printSS(cb_in->sub));
	fprintf(stderr, "cb_in->my_sup: %s\n", printSS(cb_in->my_sup));
	fprintf(stderr, "cb_in->neigh_sup: %s\n", printSS(cb_in->neigh_sup));
	fprintf(stderr, "cb_in->dcb_out->sub: %s\n", printSS(cb_in->dcb_out->sub));
	fprintf(stderr, "cb_in->dcb_out->sup: %s\n", printSS(cb_in->dcb_out->sup));
#endif
	
	fix_csum(ip, tcp);
}

/*
  TCP Retransmission methods
 */
void DyscoAgentIn::retransmissionHandler() {
	if(!dc)
		return;
	
	PacketBatch* batch = new PacketBatch();
	batch->clear();

	mutex* mtx = dc->getMutex(this->index, devip);
	if(!mtx)
		return;
	
	//mtx->lock();
	
	LinkedList<Packet>* list = dc->getRetransmissionList(this->index, devip);
	if(!list) {
		//mtx->unlock();
		
		return;
	}

	uint64_t now_ts = tsc_to_ns(rdtsc());
	LNode<bess::Packet>* aux;
	LNode<bess::Packet>* node = (list->getHead())->next;
	LNode<bess::Packet>* tail = list->getTail();

	while(node != tail) {
		if(node->cnt == 0) {
			//First transmission
			node->cnt++;
			batch->add(&node->element);
			node->ts = now_ts;
		} else {
			if(isEstablished(&node->element) || node->cnt > CNTLIMIT) {
				//If state is Established then don't need to retransmit
				aux = node->next;
				list->remove(node);
				node = aux;
				//should remove in hashtable
				continue;
			}

#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn-Retransmission] %lu - %lu = %lu (TIMEOUT: %lu).\n", ns.c_str(), now_ts, node->ts, now_ts-node->ts, DyscoAgentIn::timeout);
#endif
			
			if(now_ts - node->ts > DyscoAgentIn::timeout) {
				node->cnt++;
				batch->add(&node->element);
				node->ts = now_ts;
			}
		}
		
		node = node->next;
	}

	//mtx->unlock();

	if(batch->cnt() != 0) {
#ifdef DEBUG
		fprintf(stderr, "Calling RunChooseModule with %u packets to retransmit.\n", batch->cnt());
#endif
		RunChooseModule(1, batch);
	}
}

bool DyscoAgentIn::processReceivedPacket(Tcp* tcp) {
	uint32_t key = tcp->ack_num.value();
	
	mutex* mtx = dc->getMutex(this->index, devip);
	if(!mtx)
		return false;
	
	mtx->lock();
	
	unordered_map<uint32_t, LNode<Packet>*>* hash_received = dc->getHashReceived(this->index, devip);
	if(!hash_received) {
		mtx->unlock();
		
		return false;
	}

	LNode<bess::Packet>* node = hash_received->operator[](key);
	if(node) {
		delete node;
		hash_received->erase(key);
			
		mtx->unlock();
		
		return true;
	}

	mtx->unlock();
	
	return false;
}

bool DyscoAgentIn::isEstablished(Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + (ip->header_length << 2));

	DyscoTcpSession ss;
	ss.sip = ip->dst.raw_value();
	ss.dip = ip->src.raw_value();
	ss.sport = tcp->dst_port.raw_value();
	ss.dport = tcp->src_port.raw_value();

	DyscoHashIn* cb_in = dc->lookup_input_by_ss(this->index, &ss);
	if(!cb_in) {
		return false;
	}

	if(cb_in->dcb_out) {
		if(cb_in->dcb_out->state == DYSCO_ESTABLISHED) {
			return true;
		}
	}

	return false;
}

/*
 * Locking Signal methods
 */
bool DyscoAgentIn::processLockingSignalPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);
	uint8_t* lhop = (uint8_t*)(&tcpo->padding) + 1;
	(*lhop)--;
	tcp->checksum++;
	
	if(*lhop == 0) {
#ifdef DEBUG
		fprintf(stderr, "I'm the LeftAnchor\n");
#endif			
		createLockingPacket(pkt, ip, tcp, tcpo, cb_in);
		
		return true;
	} else {
#ifdef DEBUG
		fprintf(stderr, "I'm not the LeftAnchor\n");
#endif

		DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
		if(!cb_out) {
#ifdef DEBUG 
			fprintf(stderr, "cb_out not found... dropping.\n");
#endif
			return false;
		}

		eth->src_addr = cb_out->mac_sub.src_addr;
		eth->dst_addr = cb_out->mac_sub.dst_addr;
		hdr_rewrite_csum(ip, tcp, &cb_out->sub);

#ifdef DEBUG
		fprintf(stderr, "forwarding to %s.\n\n", printSS(cb_out->sub));
#endif
		
		PacketBatch out;
		out.clear();
		out.add(pkt);
		cb_out->module->RunChooseModule(1, &out);
	}

	return false;
}

CONTROL_RETURN DyscoAgentIn::processLockingPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));

#ifdef DEBUG
	fprintf(stderr, "looking for input by: %s.\n", printSS(cmsg->my_sub));
#endif

	DyscoHashIn* cb_in = dc->lookup_input_by_ss(this->index, &cmsg->my_sub);

	if(cmsg->lock_state == DYSCO_REQUEST_LOCK) {
#ifdef DEBUG
		fprintf(stderr, "processing Request Locking.\n");
#endif

		return processRequestLock(pkt, ip, tcp, cmsg, cb_in);
	} else if(cmsg->lock_state == DYSCO_ACK_LOCK) {
#ifdef DEBUG
		fprintf(stderr, "processing Ack Locking.\n");
#endif

		return processAckLock(pkt, ip , tcp, cmsg, cb_in);
		
	} else if(cmsg->lock_state == DYSCO_NACK_LOCK) {
#ifdef DEBUG
		fprintf(stderr, "processing Nack Locking.\n");
#endif
	}

	return NONE;
}





CONTROL_RETURN DyscoAgentIn::processRequestLocking(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out;
	
	cmsg->rhop--;
	if(cmsg->rhop > 0) {
#ifdef DEBUG
		fprintf(stderr, "I'm not the RightAnchor.\n");
#endif
		cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
	} else {
#ifdef DEBUG
		fprintf(stderr, "I'm the RightAnchor.\n");
#endif
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out) {
#ifdef DEBUG
		fprintf(stderr, "cb_out not found\n");
#endif
		return ERROR;
	}

#ifdef DEBUG
	fprintf(stderr, "State: %d\n", cb_out->state);
	fprintf(stderr, "Lock State: %d\n",  cb_out->lock_state);
	fprintf(stderr, "cb_out->sup: %s\n", printSS(cb_out->sup));
	fprintf(stderr, "cb_out->sub: %s\n", printSS(cb_out->sub));
	fprintf(stderr, "cb_out->is_signaler: %u\n", cb_out->is_signaler);
#endif
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_REQUEST_LOCK:
		//If is there another locking request with other RA? TODO
		if(cmsg->rhop > 0) {
			Ethernet* eth = pkt->head_data<Ethernet*>();
			eth->src_addr = cb_out->mac_sub.src_addr;
			eth->dst_addr = cb_out->mac_sub.dst_addr;
			*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
			*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
			cmsg->my_sub = cb_out->sub;
			fix_csum(ip, tcp);
#ifdef DEBUG
			if(cb_out->lock_state == DYSCO_CLOSED_LOCK) 
				fprintf(stderr, "Changing lock_state field from DYSCO_CLOSED_LOCK to DYSCO_REQUEST_LOCK.\n");
			else
				fprintf(stderr, "Changing lock_state field from DYSCO_REQUEST_LOCK to DYSCO_REQUEST_LOCK.\n");
#endif
			
			cb_out->lock_state = DYSCO_REQUEST_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;
			
			PacketBatch out;
			out.clear();
			out.add(pkt);
			cb_out->module->RunChooseModule(1, &out);
		
			return NONE;
		} else {
			Ethernet* eth = pkt->head_data<Ethernet*>();		
			Ethernet::Address macswap = eth->dst_addr;
			eth->dst_addr = eth->src_addr;
			eth->src_addr = macswap;
						
			ip->id = be16_t(rand());
			ip->ttl = 53;
			ip->checksum = 0;

			be32_t ipswap = ip->src;
			ip->src = ip->dst;
			ip->dst = ipswap;

			be16_t portswap = tcp->src_port;
			tcp->src_port = tcp->dst_port;
			tcp->dst_port = portswap;

			tcp->ack_num = tcp->seq_num + be32_t(1) + be32_t(hasPayload(ip, tcp));
			tcp->seq_num = be32_t(rand());
			tcp->flags |= Tcp::kAck;

			cmsg->rightA = ip->src.raw_value();
			cmsg->lock_state = DYSCO_ACK_LOCK;
			DyscoTcpSession ss;
			ss.sip = cmsg->my_sub.dip;
			ss.dip = cmsg->my_sub.sip;
			ss.sport = cmsg->my_sub.dport;
			ss.dport = cmsg->my_sub.sport;
			cmsg->my_sub = ss;

			if(cb_out->is_signaler) {
				//if I'm the signaler, I must know leftSS and rightSS.
				uint32_t* sc = reinterpret_cast<uint32_t*>(pkt->append(cb_out->sc_len * sizeof(uint32_t)));
				if(!sc)
					return ERROR;

				memcpy(sc, cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
#ifdef DEBUG
				fprintf(stderr, "Going to append %d ip addresses.\n", cb_out->sc_len);
#endif
			}
			
			fix_csum(ip, tcp);
#ifdef DEBUG
			if(cb_out->lock_state == DYSCO_CLOSED_LOCK)
				fprintf(stderr, "Changing lock_state field from DYSCO_CLOSED_LOCK to DYSCO_ACK_LOCK\n");
			else
				fprintf(stderr, "Changing lock_state field from DYSCO_REQUEST_LOCK to DYSCO_ACK_LOCK\n");	
#endif 
		
			cb_out->is_RA = 1;
			cb_out->lock_state = DYSCO_ACK_LOCK;
			
			return TO_GATE_1;
		}

		return NONE;
	case DYSCO_ACK_LOCK:
		//should reply a NACK message?
		return NONE;
	}
	
	return NONE;
}

CONTROL_RETURN DyscoAgentIn::processAckLocking(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out;
	
	cmsg->lhop--;
	if(cmsg->lhop > 0) {
#ifdef DEBUG
		fprintf(stderr, "I'm not the LeftAnchor.\n");
#endif
		cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
	} else {
#ifdef DEBUG
		fprintf(stderr, "I'm the LeftAnchor.\n");
#endif
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out) {
#ifdef DEBUG
		fprintf(stderr, "cb_out not found... dropping.\n");
#endif
		return ERROR;
	}

#ifdef DEBUG
	fprintf(stderr, "State: %d\n", cb_out->state);
	fprintf(stderr, "Lock State: %d\n",  cb_out->lock_state);
	fprintf(stderr, "cb_out->sup: %s\n", printSS(cb_out->sup));
	fprintf(stderr, "cb_out->sub: %s\n", printSS(cb_out->sub));
	fprintf(stderr, "cb_out->is_signaler: %u\n", cb_out->is_signaler);
#endif
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_NACK_LOCK:
		return ERROR;

	case DYSCO_ACK_LOCK:
	case DYSCO_REQUEST_LOCK:
		if(cb_out->is_LA) {
#ifdef DEBUG
			fprintf(stderr, "I'm the LeftAnchor... starting reconfiguration\n");
#endif
			tcp->checksum++; //due cmsg->lhop-- above
			return LOCK_SUCCESSFUL;
		} else {
#ifdef DEBUG
			fprintf(stderr, "I'm not the LeftAnchor... forwarding the ACK_LOCK\n");
#endif

			Ethernet* eth = pkt->head_data<Ethernet*>();
			eth->src_addr = cb_out->mac_sub.src_addr;
			eth->dst_addr = cb_out->mac_sub.dst_addr;
			*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
			*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
			cmsg->my_sub = cb_out->sub;

			if(cb_out->is_signaler) {
				//If I'm the signaler, I must know leftSS and rightSS
				uint32_t sc_sz = cb_out->sc_len * sizeof(uint32_t);
				uint32_t* sc = reinterpret_cast<uint32_t*>(pkt->append(sc_sz));
				if(!sc)
					return ERROR;

				memcpy(sc, cb_out->sc, sc_sz);
				ip->length = ip->length + be16_t(sc_sz);
#ifdef DEBUG
				fprintf(stderr, "Going to append %d ip addresses.\n", cb_out->sc_len);
#endif

				DyscoTcpSession ss;
				ss.sip = cb_in->my_sup.dip;
				ss.dip = cb_in->my_sup.sip;
				ss.sport = cb_in->my_sup.dport;
				ss.dport = cb_in->my_sup.sport;
				cmsg->rightSS = ss;
				cmsg->leftSS = cb_out->dcb_in->my_sup;
#ifdef DEBUG
				fprintf(stderr, "leftSS: %s\n", printSS(cmsg->leftSS));
				fprintf(stderr, "rightSS: %s\n", printSS(cmsg->rightSS));
#endif
			}
			
			fix_csum(ip, tcp);
			cb_out->lock_state = DYSCO_ACK_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_ACK_LOCK;
#ifdef DEBUG
			fprintf(stderr, "Changing lock_state field from DYSCO_REQUEST_LOCK to DYSCO_ACK_LOCK\n");
#endif

			PacketBatch out;
			out.clear();
			out.add(pkt);
			cb_out->module->RunChooseModule(1, &out);
			
			return NONE;
		}
	}
	
	return ERROR;
}

void DyscoAgentIn::startReconfiguration(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
	if(!cmsg)
		return;
	
	DyscoHashIn* cb_in = dc->lookup_input_by_ss(this->index, &cmsg->my_sub);
	if(!cb_in)
		return;
	
	DyscoHashOut* old_dcb = cb_in->dcb_out;
	uint32_t* sc = reinterpret_cast<uint32_t*>(cmsg + 1);

	//should ARP
	Ethernet::Address addr = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = addr;
	
	ip->ttl = 53;
	ip->src = ip->dst;
	ip->dst = be32_t(ntohl(sc[0]));

	tcp->src_port = be16_t(40000 + (rand() % 10000));
	tcp->dst_port = be16_t(50000 + (rand() % 10000));
	tcp->flags = Tcp::kSyn;
	tcp->seq_num = be32_t(old_dcb->out_iseq);
	tcp->ack_num = be32_t(old_dcb->out_iack);

	cmsg->my_sub.sip = ip->src.raw_value();
	cmsg->my_sub.dip = ip->dst.raw_value();
	cmsg->my_sub.sport = tcp->src_port.raw_value();
	cmsg->my_sub.dport = tcp->dst_port.raw_value();
	cmsg->leftIseq = htonl(old_dcb->out_iseq);
	cmsg->leftIack = htonl(old_dcb->out_iack);
	cmsg->leftIts = htonl(old_dcb->ts_in);
	cmsg->leftItsr = htonl(old_dcb->tsr_in);
	cmsg->leftIws = htons(old_dcb->ws_in);
	cmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);
	cmsg->sackOk = htonl(old_dcb->sack_ok);
	cmsg->type = DYSCO_RECONFIG;

	fix_csum(ip, tcp);

	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->super;
	rcb->sub_out.sip = ip->src.raw_value();
	rcb->sub_out.dip = ip->dst.raw_value();
	rcb->sub_out.sport = tcp->src_port.raw_value();
	rcb->sub_out.dport = tcp->dst_port.raw_value();
	
	rcb->leftIseq = old_dcb->out_iseq;
	rcb->leftIack = old_dcb->out_iack;
	rcb->leftIts = old_dcb->ts_in;
	rcb->leftItsr = old_dcb->tsr_in;
	rcb->leftIws = old_dcb->ws_in;
	rcb->leftIwsr = old_dcb->dcb_in->ws_in;
	rcb->sack_ok =old_dcb->sack_ok;

	if(!dc->insert_hash_reconfig(this->index, rcb))
		return;


	DyscoHashOut* new_dcb = new DyscoHashOut();

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
	new_dcb->dcb_in = insert_cb_out_reverse(new_dcb, 1, cmsg);
	dc->insert_hash_input(this->index, new_dcb->dcb_in);

	new_dcb->dcb_in->is_reconfiguration = 1;
		
	memcpy(&new_dcb->cmsg, cmsg, sizeof(DyscoControlMessage));
	new_dcb->is_reconfiguration = 1;

	old_dcb->old_path = 1;
	//TEST
	if(old_dcb->dcb_in)
		old_dcb->dcb_in->two_paths = 1;

	if(ntohs(cmsg->semantic) == STATE_TRANSFER)
		old_dcb->state_t = 1;

	new_dcb->state = DYSCO_SYN_SENT;










	
	
	//uint32_t* sc = reinterpret_cast<uint32_t*>(cmsg + 1);
	//uint32_t sc_len = (hasPayload(ip, tcp) - sizeof(DyscoControlMessage))/sizeof(uint32_t);

#ifdef DEBUG
	fprintf(stderr, "cb_in->dcb_out->sup: %s\n", printSS(cb_in->dcb_out->sup));
	fprintf(stderr, "cb_in->dcb_out->sub: %s\n", printSS(cb_in->dcb_out->sub));
	fprintf(stderr, "my_sub: %s\n", printSS(cmsg->my_sub));
	fprintf(stderr, "super: %s\n", printSS(cmsg->super));
	fprintf(stderr, "leftSS: %s\n", printSS(cmsg->leftSS));
	fprintf(stderr, "rightSS: %s\n", printSS(cmsg->rightSS));
	fprintf(stderr, "leftA: %s\n", printIP(cmsg->leftA));
	fprintf(stderr, "rightA: %s\n", printIP(cmsg->rightA));
	fprintf(stderr, "type: %u\n", cmsg->type);
#endif
	
	PacketBatch out;
	out.clear();
	out.add(pkt);
	RunChooseModule(1, &out);	
}

Packet* DyscoAgentIn::createAckLocking(Packet* pkt, Ipv4* ip, Tcp* tcp) {
#ifdef DEBUG
	fprintf(stderr, "Going to create an ACK for SYN+ACK (DYSCO_ACK_LOCK).\n");
#endif
	Packet* newpkt = Packet::Alloc();

	newpkt->set_total_len(sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp));
	newpkt->set_data_len(sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp));
	
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->dst_addr = eth->src_addr;
	neweth->src_addr = eth->dst_addr;
	neweth->ether_type = be16_t(Ethernet::Type::kIpv4);

	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->header_length = 5;
	newip->version = 4;
	newip->type_of_service = 0;
	newip->length = be16_t(sizeof(Ipv4) + sizeof(Tcp));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = 53;
	newip->protocol = Ipv4::kTcp;
	newip->checksum = 0;
	newip->src = ip->dst;
	newip->dst = ip->src;

	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = tcp->dst_port;
	newtcp->dst_port = tcp->src_port;
	newtcp->seq_num = tcp->ack_num;
	newtcp->ack_num = tcp->seq_num + be32_t(hasPayload(ip, tcp) + 1);
	newtcp->reserved = 0;
	newtcp->offset = 5;
	newtcp->flags = Tcp::kAck;
	newtcp->window = tcp->window;
	newtcp->checksum = 0;
	newtcp->urgent_ptr = be16_t(0);

	fix_csum(newip, newtcp);

	return newpkt;
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
