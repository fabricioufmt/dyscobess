#include "dysco_agent_in.h"

const Commands DyscoAgentIn::cmds = {
	{"setup", "DyscoAgentArg", MODULE_CMD_FUNC(&DyscoAgentIn::CommandSetup), Command::THREAD_UNSAFE}
};

DyscoAgentIn::DyscoAgentIn() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
	received_hash = new unordered_map<uint32_t, LNode<Packet>*>();
}

CommandResponse DyscoAgentIn::CommandSetup(const bess::pb::DyscoAgentArg& arg) {
	gate_idx_t ogate_idx = 0;

	if(!is_active_gate<bess::OGate>(ogates(), ogate_idx))
		return CommandFailure(EINVAL, "ERROR: Output gate 0 is not active.");

	bess::OGate* ogate = ogates()[ogate_idx];
	DyscoPortOut* dysco_port_out = reinterpret_cast<DyscoPortOut*>(ogate->next());
	if(!dysco_port_out)
		return CommandFailure(EINVAL, "ERROR: DyscoPortOut is not available.");
	
	DyscoVPort* dysco_vport = reinterpret_cast<DyscoVPort*>(dysco_port_out->port_);
	if(!dysco_vport)
		return CommandFailure(EINVAL, "ERROR: DyscoVPort is not available.");
	
	const auto& it1 = ModuleGraph::GetAllModules().find(DYSCOCENTER_MODULENAME);
	if(it1 == ModuleGraph::GetAllModules().end())
		return CommandFailure(EINVAL, "ERROR: DyscoCenter is not available.");

	dc = reinterpret_cast<DyscoCenter*>(it1->second);

	const auto& it2 = ModuleGraph::GetAllModules().find(arg.agent().c_str());
	if(it2 == ModuleGraph::GetAllModules().end())
		return CommandFailure(EINVAL, "ERROR: DyscoAgentOut is not available.");
	
	agent = reinterpret_cast<DyscoAgentOut*>(it2->second);

	port = dysco_vport;
	ns = dysco_vport->ns;
	devip = dysco_vport->devip;
	index = dc->get_index(ns, devip);
	
	return CommandSuccess();
}

void DyscoAgentIn::ProcessBatch(PacketBatch* batch) {
	if(!dc) {
		RunChooseModule(0, batch);
		return;
	}
	
	PacketBatch out;
	out.clear();

	Tcp* tcp;
	Ipv4* ip;
	Packet* pkt;
	Packet* newpkt;
	bool removed;
	Ethernet* eth;
	size_t ip_hlen;
	DyscoHashIn* cb_in;
	
	for(int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		if(!pkt)
			continue;
		
		eth = pkt->head_data<Ethernet*>();
		if(!isIP(eth)) {
			out.add(pkt);
			continue;
		}

		ip = reinterpret_cast<Ipv4*>(eth + 1);
		if(!isTCP(ip)) {
			out.add(pkt);
			continue;
		}
		
		ip_hlen = ip->header_length << 2;
		tcp = reinterpret_cast<Tcp*>((uint8_t*)ip + ip_hlen);

		cb_in = dc->lookup_input(this->index, ip, tcp);
		removed = processReceivedPacket(ip, tcp);

		if(tcp->flags == Tcp::kFin)
			fprintf(stderr, "[%s][DyscoAgentIn] receives %s FIN segment [%X:%X]\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
		else if(tcp->flags == (Tcp::kFin | Tcp::kAck))
			fprintf(stderr, "[%s][DyscoAgentIn] receives %s FIN+ACK segment [%X:%X]\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
		
		if(isLockingSignalPacket(tcp)) {
			fprintf(stderr, "[%s] Receives Locking Signal Packet.\n", ns.c_str());
			
			newpkt = processLockingSignalPacket(pkt, eth, ip, tcp, cb_in);
			if(newpkt) {
				agent->forward(newpkt, true);
				createAckLockingSignalPacket(pkt, eth, ip, tcp);
				agent->forward(pkt);
				
				continue;
			}
		} else if(isLockingPacket(ip, tcp)) {
			fprintf(stderr, "[%s] Receives Locking Packet.\n", ns.c_str());

			newpkt = processLockingPacket(pkt, eth, ip, tcp);
			if(newpkt) {
				agent->forward(newpkt);
				
				continue;
			}
		} else if(isReconfigPacket(ip, tcp, cb_in)) {
			fprintf(stderr, "[%s] Receives Reconfig Packet.\n", ns.c_str());

			if(control_input(pkt, eth, ip, tcp, cb_in)) {
				out.add(pkt);
			}
			
		} else {
			if(removed) {
				continue;
			}
			
			if(input(pkt, eth, ip, tcp, cb_in)) {
				out.add(pkt);
			}
			if(tcp->flags == Tcp::kFin)
				fprintf(stderr, "[%s][DyscoAgentIn] forwards %s FIN segment [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#ifdef DEBUG
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#endif
		}
	}
	
	batch->clear();
	RunChooseModule(0, &out);
}

bool DyscoAgentIn::processReceivedPacket(Ipv4* ip, Tcp* tcp) {
	uint32_t key = tcp->ack_num.value();

	if(tcp->flags == (Tcp::kSyn | Tcp::kAck) && hasPayload(ip, tcp)) {
		DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
		if(cmsg->type == DYSCO_LOCK) {
			key -= hasPayload(ip, tcp);
		}
	}

	LNode<Packet>* node = received_hash->operator[](key);

	if(node) {
		received_hash->erase(key);
		agent->remove(node);
		
		return true;
	}

	return false;
}
















bool DyscoAgentIn::isReconfigPacket(Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(ip->dst.raw_value() != devip) {
		return false;
	}

	uint32_t payload_len = hasPayload(ip, tcp);
	
	if(isTCPSYN(tcp, true)) {
		if(!cb_in) {
			if(payload_len) {
				DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
				return cmsg->type == DYSCO_RECONFIG;
			}

			return false;
		}

		if(!cb_in->dcb_out) {
			return false;
		}

		if(cb_in->dcb_out->lock_state != DYSCO_ACK_LOCK) {
			return false;
		}
		
		if(cb_in->dcb_out->state == DYSCO_SYN_RECEIVED && payload_len > 0) {
			return true;
		}
		
		return false;
	}

	if(!cb_in)
		return false;

	if(isTCPSYN(tcp) && isTCPACK(tcp)) {
		if(cb_in->is_reconfiguration) {
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

		if(cb_in->sack_ok)
			tcp_sack(tcp, cb_in->ack_delta, cb_in->ack_add);

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
		fprintf(stderr, "[%s][DyscoAgentIn] There is a NAT.\n", ns.c_str());
#endif
		cb_in->my_sup = cb_in->sub;
		cb_in->my_sup.dip = neigh_supss->dip;
		cb_in->my_sup.dport = neigh_supss->dport;
	} else {
#ifdef DEBUG
		fprintf(stderr, "[%s][DyscoAgentIn] There is not a NAT.\n", ns.c_str());
#endif
		cb_in->my_sup.sip = neigh_supss->sip;
		cb_in->my_sup.dip = neigh_supss->dip;
		cb_in->my_sup.sport = neigh_supss->sport;
		cb_in->my_sup.dport = neigh_supss->dport;
	}

	if(payload_sz > 2 * sizeof(DyscoTcpSession) + sizeof(uint32_t)) {
		uint32_t sc_len = (payload_sz - 2 * sizeof(DyscoTcpSession))/sizeof(uint32_t);

		DyscoHashOut* cb_out = new DyscoHashOut();
		
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
		fprintf(stderr, "NAT crossed -- inserting a fake cb_out with neigh_sup.\n");
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

	cb_out->in_iseq = tcp->seq_num.value();
	cb_out->in_iack = tcp->ack_num.value();

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
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "[%s]in_two_paths_ack method.\n", ns.c_str());
#endif
	uint32_t ack_seq = tcp->ack_num.value();

	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out) {
		return false;
	}

	if(cb_out->old_path) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_out is old path\n");
#endif
		if(cb_out->state_t) {
			if(cb_out->state == DYSCO_ESTABLISHED) {
				cb_in->two_paths = 0;
			}
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "cb_out->seq_cutoff=%X, ack_seq=%X, !after(cb_out->seq_cutoff, ack_seq)==%u\n", cb_out->seq_cutoff, ack_seq, !after(cb_out->seq_cutoff, ack_seq));
#endif
			if(!after(cb_out->seq_cutoff, ack_seq)) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "setting (old_path) use_np_seq = 1.... because !after(cb_out->seq_cutoff, ack_seq) == %X, %X\n", cb_out->seq_cutoff, ack_seq);
#endif
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
			}
		}
	} else {
		cb_out = cb_out->other_path;
		if(!cb_out) {
			return false;
		}
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "cb_out is new path\n");
#endif
		if(cb_out->state_t && cb_out->state == DYSCO_ESTABLISHED) {
			cb_in->two_paths = 0;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "cb_out->seq_cutoff=%X, ack_seq=%X, !after(cb_out->seq_cutoff, ack_seq)==%u\n", cb_out->seq_cutoff, ack_seq, !after(cb_out->seq_cutoff, ack_seq));
#endif
			if(!after(cb_out->seq_cutoff, ack_seq)) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "[%s]setting (new_path) use_np_seq = 1.... because !after(cb_out->seq_cutoff, ack_seq) == %X, %X\n", ns.c_str(), cb_out->seq_cutoff, ack_seq);
#endif
				cb_out->use_np_seq = 1;
				cb_in->two_paths = 0;
				
			}
		}
	}

	return true;
}

//L.683
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in, uint32_t) {
	DyscoHashOut* cb_out = cb_in->dcb_out;
	if(!cb_out)
		return false;

	if(!cb_out->old_path) {
		DyscoHashOut* old_out = cb_out->other_path;

		if(!old_out)
			return false;

		if(cb_out->state != DYSCO_CLOSED) {
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
				if(before(seq, old_out->ack_cutoff))
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
bool DyscoAgentIn::input(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t payload_sz = hasPayload(ip, tcp);

	if(!cb_in) {
		if(isTCPSYN(tcp, true) && payload_sz)
			rx_initiation_new(pkt, ip, tcp, payload_sz);
		
		return true;
	}

	if(isTCPACK(tcp, true)) {
		if(cb_in->dcb_out->old_path && cb_in->dcb_out->state == DYSCO_LAST_ACK) {
			cb_in->dcb_out->state = DYSCO_CLOSED;

			return false;
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
		
		return true;
	}
	
	if(cb_in->two_paths) {
		if(!payload_sz)
			in_two_paths_ack(tcp, cb_in);
		else if(!in_two_paths_data_seg(tcp, cb_in, payload_sz))
			return true;
	}
	
	if(isTCPFIN(tcp)) {
		fprintf(stderr, "[%s] DEBUB INFO:\n", ns.c_str());
		fprintf(stderr, "[%s] cb_in->dcb_out->old_path = %u\n", ns.c_str(), cb_in->dcb_out->old_path);
		fprintf(stderr, "[%s] cb_in->dcb_out->is_LA = %u\n", ns.c_str(), cb_in->dcb_out->is_LA);
		fprintf(stderr, "[%s] cb_in->dcb_out->is_RA = %u\n", ns.c_str(), cb_in->dcb_out->is_RA);
		fprintf(stderr, "[%s] cb_in->dcb_out->state = %d\n", ns.c_str(), cb_in->dcb_out->state);
	}
	
	if(cb_in->dcb_out->old_path && (cb_in->dcb_out->is_LA || cb_in->dcb_out->is_RA) && (cb_in->dcb_out->state == DYSCO_FIN_WAIT_1 || cb_in->dcb_out->state == DYSCO_CLOSING || cb_in->dcb_out->state == DYSCO_CLOSED)) {
		fprintf(stderr, "[%s] state = DYSCO_FIN_WAIT_1, DYSCO_CLOSING or DYSCO_CLOSED.\n", ns.c_str());
		if(tcp->flags & Tcp::kFin) {
			if(tcp->flags == Tcp::kFin) {
				fprintf(stderr, "[%s] changing to DYSCO_CLOSING.\n", ns.c_str());
				cb_in->dcb_out->state = DYSCO_CLOSING;
			} else {
				fprintf(stderr, "[%s] changing to DYSCO_CLOSED.\n", ns.c_str());
				cb_in->dcb_out->state = DYSCO_CLOSED;
			}
			
			createAck(pkt, eth, ip, tcp);
			agent->forward(pkt);

			fprintf(stderr, "[%s] forwarding ACK for FIN or FIN+ACK.\n", ns.c_str());
			return false;
		}
	}

	if(cb_in->dcb_out->old_path && (cb_in->dcb_out->is_LA || cb_in->dcb_out->is_RA) && cb_in->dcb_out->state == DYSCO_ESTABLISHED && isTCPFIN(tcp)) {
		fprintf(stderr, "[%s][DyscoAgentIn] receives %s FIN segment on ESTABLISHED state [%X:%X].\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());

		if(payload_sz) {
			fprintf(stderr, "[%s] there are data on packet, should remove FIN flag, forward to app and create a new Packet to answer FIN segment\n", ns.c_str());

			tcp->flags -= Tcp::kFin;
			tcp->checksum += htons(Tcp::kFin);

			fprintf(stderr, "[%s] should answer to a FIN+ACK and change to DYSCO_CLOSED\n", ns.c_str());
			Packet* finpkt = createFinAckPacket(eth, ip, tcp, payload_sz);
			agent->forward(finpkt, true);
			cb_in->dcb_out->state = DYSCO_CLOSED;

			Ipv4* newip = reinterpret_cast<Ipv4*>(finpkt->head_data<Ethernet*>() + 1);
			Tcp* newtcp = reinterpret_cast<Tcp*>((uint8_t*)newip + (newip->header_length * 4));
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s FIN [%X:%X]\n\n", ns.c_str(), printPacketSS(newip, newtcp), newtcp->seq_num.raw_value(), newtcp->ack_num.raw_value());

			
		} else {
		
			fprintf(stderr, "[%s] should answer to a FIN+ACK too and change to DYSCO_CLOSED\n", ns.c_str());
			Packet* finpkt = createFinAckPacketSS(cb_in->dcb_out);
			agent->forward(finpkt, true);
			cb_in->dcb_out->state = DYSCO_CLOSED;

			Ipv4* newip = reinterpret_cast<Ipv4*>(finpkt->head_data<Ethernet*>() + 1);
			Tcp* newtcp = reinterpret_cast<Tcp*>((uint8_t*)newip + (newip->header_length * 4));
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s FIN [%X:%X]\n\n", ns.c_str(), printPacketSS(newip, newtcp), newtcp->seq_num.raw_value(), newtcp->ack_num.raw_value());

			return false;
		}
	}
	
	/* else {
		if(payload_sz) {
			if(cb_in->dcb_out) {
				cb_in->dcb_out->ack_cutoff = tcp->seq_num.value() + payload_sz;
			}
		}
		}*/
	
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

	//fprintf(stderr, "[%s] receives %X as cutoff at DYSCO_SYN message.\n", ns.c_str(), ntohl(cmsg->seqCutoff));
	
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
	/*
	if(strcmp(ns.c_str(), "/var/run/netns/RA") == 0) {
		fprintf(stderr, "[%s] compute_deltas_out\n", ns.c_str());
		fprintf(stderr, "[%s] cb_out->sub: %s\n", ns.c_str(), printSS(cb_out->sub));
		fprintf(stderr, "[%s] cb_out->in_iack < cb_out->out_iack ?\n", ns.c_str());
		fprintf(stderr, "[%s] %X < %X ?\n", ns.c_str(), cb_out->in_iack, cb_out->out_iack);
	}
	*/
	if(cb_out->in_iack < cb_out->out_iack) {
		cb_out->ack_delta = cb_out->out_iack - cb_out->in_iack;
		cb_out->ack_add = 1;
	} else {
		cb_out->ack_delta = cb_out->in_iack - cb_out->out_iack;
		cb_out->ack_add = 0;
	}

#ifdef DEBUG_RECONFIG
	if(strcmp(ns.c_str(), "/var/run/netns/RA") == 0) {
		fprintf(stderr, "[%s] cb_out->ack_delta = %X (ack_add: %u)\n", ns.c_str(), cb_out->ack_delta, cb_out->ack_add);
	}
#endif
	
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

	cb_in->my_sup = cmsg->rightSS;
	
	DyscoHashOut* old_out = dc->lookup_output_by_ss(this->index, &local_ss);
	if(!old_out) {
		dc->remove_hash_input(this->index, cb_in);
		delete cb_in;
		dc->remove_hash_reconfig(this->index, rcb);
		delete rcb;

		return false;
	} else {
		if(old_out->is_nat) {
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
	//cb_out->other_path = old_out;
	
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

bool DyscoAgentIn::control_reconfig_in(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, uint8_t*, DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;

	size_t tcp_hlen = tcp->offset << 2;
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
	uint32_t payload_sz = ip->length.value() - (ip->header_length << 2) - tcp_hlen;
		
	if(isToRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "It's the right anchor.\n");
#endif
		
		cb_in = new DyscoHashIn();
		cb_in->module = this;
		cb_in->sub = rcb->sub_in;
		cb_in->seq_delta = cb_in->ack_delta = 0;

		cb_in->in_iseq = rcb->leftIseq;
		cb_in->in_iack = rcb->leftIack;
				
		cb_in->is_reconfiguration = 1;
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
		cb_out = build_cb_in_reverse(ip, rcb);

		if(!cb_out) {
			dc->remove_hash_input(this->index, cb_in);
			delete cb_in;
			dc->remove_hash_reconfig(this->index, rcb);
			delete rcb;
			
			return false;
		}

		parse_tcp_syn_opt_r(tcp, cb_in);
		
		cb_in->dcb_out = cb_out;
		cb_out->dcb_in = cb_in;
		
		dc->insert_hash_input(this->index, cb_in);
		
		createSynAck(pkt, eth, ip, tcp);
		
		if(!control_config_rightA(rcb, cmsg, cb_in, cb_out)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "control_config_rightA returns false\n");
#endif
			return false;
		}
		
		//replace_cb_rightA method from control_output
		DyscoHashOut* old_out = rcb->old_dcb;
		DyscoHashOut* new_out = rcb->new_dcb;
		//uint32_t seq_cutoff = old_out->seq_cutoff;
		//uint32_t ack_cutoff = ntohl(cmsg->seqCutoff);

		old_out->old_path = 1;
		old_out->other_path = new_out;
		new_out->other_path = old_out;
		cb_in->two_paths = 1;
		old_out->dcb_in->two_paths = 1;

		/*
		uint32_t delta;
		if(new_out->in_iack < new_out->out_iack) {
			delta = new_out->out_iack - new_out->in_iack;
			ack_cutoff -= delta;
		} else {
			delta = new_out->in_iack - new_out->out_iack;
			ack_cutoff += delta;
		}
		
		old_out->ack_cutoff = ack_cutoff;
		*/
		parse_tcp_syn_opt_s(tcp, new_out);
		
		new_out->state = DYSCO_SYN_RECEIVED;

		agent->forward(pkt, true);
		
		return false;
	}

#ifdef DEBUG_RECONFIG
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

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "neigh_supss: %s\n", printSS(cmsg->super));
	fprintf(stderr, "leftSS: %s\n", printSS(cmsg->leftSS));
#endif
	
	if(sc_len > 1) {
#ifdef DEBUG_RECONFIG
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
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s] insert_pending_reconfig returns false\n", ns.c_str());
#endif
			dc->remove_hash_input(this->index, cb_in);
			delete cb_in;
			dc->remove_hash_output(this->index, cb_out);
			delete cb_out;

			return false;
		}
	}

	if(!dc->insert_hash_input(this->index, cb_in)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] insert_hash_input returns false\n", ns.c_str());
#endif
		dc->remove_hash_input(this->index, cb_in);
		delete cb_in;

		return false;
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
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "NOSTATE_TRANSFER or sc_len < 2\n");
#endif
		remove_sc(pkt, ip, payload_sz);
		insert_tag(pkt, ip, tcp);

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm going to change session from %s to %s\n", printPacketSS(ip, tcp), printSS(cb_in->my_sup));
#endif
		hdr_rewrite_full_csum(ip, tcp, &cb_in->my_sup);
	
		return true;
	}

	return false;
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

bool DyscoAgentIn::control_input(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoCbReconfig* rcb;
	DyscoControlMessage* cmsg = 0;
	size_t tcp_hlen = tcp->offset << 2;

	if(isTCPSYN(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] DYSCO_SYN message.\n", ns.c_str());
#endif
		uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
		cmsg = reinterpret_cast<DyscoControlMessage*>(payload);

		rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->rightSS); 
		if(rcb) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's retransmission of SYN.\n\n");
#endif
			return false;
		}

		rcb = insert_rcb_control_input(ip, tcp, cmsg);
		if(!rcb) {
			return false;
		}

		return control_reconfig_in(pkt, eth, ip, tcp, payload, rcb, cmsg);
		
	} else if(isTCPSYN(tcp) && isTCPACK(tcp)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] DYSCO_SYN_ACK message.\n", ns.c_str());
#endif
		if(!cb_in) {
			return false;
		}

		cmsg = &cb_in->cmsg;
		if(!cmsg) {
			return false;
		}

		if(ip->dst.value() == ntohl(cmsg->leftA)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's the left anchor.\n");
#endif
			
			DyscoHashOut* cb_out = cb_in->dcb_out;
			if(!cb_out) {
				return false;
			}

			if(cb_out->state == DYSCO_ESTABLISHED) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "Is a retransmission packet (already ESTABLISHED state)\n");
#endif
				createAck(pkt, eth, ip, tcp);
				
				return false;
			}
			
			createAck(pkt, eth, ip, tcp);
			
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_out->sup);
			if(!rcb) {
				return false;
			}
			
			DyscoHashOut* new_dcb = rcb->new_dcb;
			DyscoHashOut* old_dcb = rcb->old_dcb;

			old_dcb->old_path = 1;
			old_dcb->other_path = new_dcb;
			new_dcb->other_path = old_dcb;

			if(!old_dcb->valid_ack_cut) {
				old_dcb->valid_ack_cut = 1;
				old_dcb->use_np_ack = 1;
			}
			
			cb_out->state = DYSCO_ESTABLISHED;
			new_dcb->state = DYSCO_ESTABLISHED; //the same, right?
			
			cb_in->is_reconfiguration = 0;
			
			if(!rcb->old_dcb->state_t) {
				if(!old_dcb) {
					return false;
				}
			}

			agent->forward(pkt);

			Packet* finpkt = createFinAckPacketSS(old_dcb);
			agent->forward(finpkt, true);
			old_dcb->state = DYSCO_FIN_WAIT_1;

			Ipv4* newip = reinterpret_cast<Ipv4*>(finpkt->head_data<Ethernet*>() + 1);
			Tcp* newtcp = reinterpret_cast<Tcp*>((uint8_t*)newip + (newip->header_length * 4));
			fprintf(stderr, "[%s][DyscoAgentIn] forwards %s FIN+ACK [%X:%X]\n\n", ns.c_str(), printPacketSS(newip, newtcp), newtcp->seq_num.raw_value(), newtcp->ack_num.raw_value());
			
			return false;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It isn't left anchor.\n");
#endif		
			set_ack_number_out(tcp, cb_in);
			in_hdr_rewrite_csum(ip, tcp, cb_in);

			return true;
		}
	} else if(isTCPACK(tcp, true)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] DYSCO_ACK message.\n", ns.c_str());
#endif
		cmsg = &cb_in->cmsg;
		
		cb_in->is_reconfiguration = 0;
		
		if(isToRightAnchor(ip, cmsg)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's the right anchor.\n");
#endif
			
			rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->my_sup);
			if(!rcb) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "Looking for %s on hash_reconfig, NOT FOUND.\n", printSS(cb_in->my_sup));
#endif
				rcb = dc->lookup_reconfig_by_ss(this->index, &cb_in->neigh_sup);
				if(!rcb) {
#ifdef DEBUG_RECONFIG
					fprintf(stderr, "Looking for %s on hash_reconfig, NOT FOUND.\n", printSS(cb_in->neigh_sup));
#endif
					return false;
				}
			}
			
			DyscoHashOut* old_out = rcb->old_dcb;
			DyscoHashOut* new_out = rcb->new_dcb;
			
			if(!old_out || !new_out) {
				return false;
			}

			old_out->old_path = 1;

			if(new_out->state == DYSCO_SYN_RECEIVED) {
				new_out->state = DYSCO_ESTABLISHED;
			}

			/*
			if(!old_out->state_t) {
				old_out->ack_cutoff = old_out_ack_cutoff;
				old_out->valid_ack_cut = 1;
			}
			*/
			return false;
		}
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "It isn't the right anchor.\n");
#endif
		set_ack_number_out(tcp, cb_in);
		in_hdr_rewrite_csum(ip, tcp, cb_in);
		
		return true;
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
	
	return false;
}

/*
  Auxiliary methods
 */
void DyscoAgentIn::createAck(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
	Ethernet::Address macswap = eth->dst_addr;
	eth->dst_addr = eth->src_addr;
	eth->src_addr = macswap;

	uint32_t tcp_opt_len = (tcp->offset << 2) - sizeof(Tcp);
	
	be32_t ipswap = ip->dst;
	ip->dst = ip->src;
	ip->src = ipswap;
	ip->ttl = TTL;
	ip->id = be16_t(rand() % PORT_RANGE);
	ip->length = ip->length - be16_t(tcp_opt_len);
	
	be16_t pswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = pswap;

	be32_t seqswap = tcp->seq_num;
	tcp->seq_num = be32_t(tcp->ack_num.value());
	tcp->ack_num = be32_t(seqswap.value() + 1);
	tcp->flags = Tcp::kAck;
	tcp->offset = 5;

	pkt->trim(tcp_opt_len);

	fix_csum(ip, tcp);
}

void DyscoAgentIn::createSynAck(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
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
	tcp->ack_num = seqswap + be32_t(1);
	tcp->flags |= Tcp::kAck;
	pkt->trim(payload_len);

	fix_csum(ip, tcp);
}

Packet* DyscoAgentIn::createFinAckPacket(Ethernet* eth, Ipv4* ip, Tcp* tcp, uint32_t payload) {
	Packet* pkt = Packet::Alloc();
	pkt->set_data_off(SNBUF_HEADROOM);

	uint16_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp);

	pkt->set_data_len(size);
	pkt->set_total_len(size);

	Ethernet* neweth = pkt->head_data<Ethernet*>();
	neweth->dst_addr = eth->src_addr;
	neweth->src_addr = eth->dst_addr;
	neweth->ether_type = be16_t(Ethernet::Type::kIpv4);

	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->version = 4;
	newip->header_length = 5;
	newip->type_of_service = 0;
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = ip->src;

	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->dst_port = tcp->src_port;
	newtcp->src_port = tcp->dst_port;
	newtcp->seq_num = tcp->ack_num;
	newtcp->ack_num = tcp->seq_num + be32_t(payload + 1);
	newtcp->offset = 5;
	newtcp->reserved = 0;
	newtcp->flags = (Tcp::kFin | Tcp::kAck);
	newtcp->window = be16_t(65535);
	newtcp->urgent_ptr = be16_t(0);

	fix_csum(newip, newtcp);

	return pkt;
}

Packet* DyscoAgentIn::createFinAckPacketSS(DyscoHashOut* cb_out) {
	Packet* pkt = Packet::Alloc();
	pkt->set_data_off(SNBUF_HEADROOM);

	uint16_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp);

	pkt->set_data_len(size);
	pkt->set_total_len(size);

	Ethernet* eth = pkt->head_data<Ethernet*>();
	eth->dst_addr = cb_out->mac_sub.dst_addr;
	eth->src_addr = cb_out->mac_sub.src_addr;
	eth->ether_type = be16_t(Ethernet::Type::kIpv4);

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	ip->version = 4;
	ip->header_length = 5;
	ip->type_of_service = 0;
	ip->length = be16_t(size - sizeof(Ethernet));
	ip->id = be16_t(rand());
	ip->fragment_offset = be16_t(0);
	ip->ttl = TTL;
	ip->protocol = Ipv4::kTcp;
	*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
	*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;

	Tcp* tcp = reinterpret_cast<Tcp*>(ip + 1);
	*((uint16_t*)(&tcp->src_port)) = cb_out->sub.sport;
	*((uint16_t*)(&tcp->dst_port)) = cb_out->sub.dport;
	tcp->seq_num = be32_t(cb_out->last_seq);
	tcp->ack_num = be32_t(cb_out->last_ack);
	tcp->offset = 5;
	tcp->reserved = 0;
	tcp->flags = (Tcp::kFin | Tcp::kAck);
	tcp->window = be16_t(65535);
	tcp->urgent_ptr = be16_t(0);

	fix_csum(ip, tcp);

	return pkt;
}

/*
  - remove TCP Option
  - increase Packet buffer (sizeof(DyscoControlMessage))
 */


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
Packet* DyscoAgentIn::processLockingSignalPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return 0;

	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>((uint8_t*)tcp + sizeof(Tcp));
	uint8_t* lhop = (uint8_t*)(&tcpo->padding) + 1;
	(*lhop)--;
	tcp->checksum++;
	
	if(*lhop == 0) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm the LeftAnchor\n");
#endif			
		return createLockingPacket(pkt, eth, ip, tcp, tcpo, cb_in);
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm not the LeftAnchor\n");
#endif

		DyscoHashOut* cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
		if(!cb_out) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "I'm looking for %s on output_hash... not found.\n", printSS(cb_in->my_sup));
#endif
			return 0;
		}

		eth->src_addr = cb_out->mac_sub.src_addr;
		eth->dst_addr = cb_out->mac_sub.dst_addr;
		hdr_rewrite_csum(ip, tcp, &cb_out->sub);

#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm going to forward to %s.\n\n", printSS(cb_out->sub));
#endif
		
		PacketBatch out;
		out.clear();
		out.add(pkt);
		cb_out->module->RunChooseModule(1, &out);
	}

	return 0;
}

Packet* DyscoAgentIn::createLockingPacket(Packet*, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoTcpOption* tcpo, DyscoHashIn* cb_in) {
	Packet* newpkt = Packet::Alloc();
	newpkt->set_data_off(SNBUF_HEADROOM);

	uint16_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage);

	newpkt->set_data_len(size);
	newpkt->set_total_len(size);
	
	uint8_t rhop = tcpo->padding & 0xff;
	
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->dst_addr = eth->src_addr;
	neweth->src_addr = eth->dst_addr;
	neweth->ether_type = be16_t(Ethernet::Type::kIpv4);

	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->version = 4;
	newip->header_length = 5;
	newip->type_of_service = 0;
	//newip->length = ip->length - be16_t(tcpo->len) + be16_t(sizeof(DyscoControlMessage));
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = ip->src;
	
	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = be16_t(rand());
	newtcp->dst_port = be16_t(rand());
	newtcp->seq_num = be32_t(rand());
	newtcp->ack_num = be32_t(0);
	newtcp->offset = 5;
	newtcp->reserved = 0;
	newtcp->flags = Tcp::kSyn;
	newtcp->window = tcp->window;
	newtcp->urgent_ptr = be16_t(0);

	cb_in->dcb_out->is_LA = 1;
	cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;

	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
	
	memset(cmsg, 0, sizeof(DyscoControlMessage));	
	cmsg->type = DYSCO_LOCK;
	cmsg->lock_state = DYSCO_REQUEST_LOCK;
	cmsg->leftA = newip->src.raw_value();
	cmsg->my_sub.sip = cb_in->sub.dip;
	cmsg->my_sub.dip = cb_in->sub.sip;
	cmsg->my_sub.sport = cb_in->sub.dport;
	cmsg->my_sub.dport = cb_in->sub.sport;
	cmsg->super.sip = cb_in->my_sup.dip;
	cmsg->super.dip = cb_in->my_sup.sip;
	cmsg->super.sport = cb_in->my_sup.dport;
	cmsg->super.dport = cb_in->my_sup.sport;
	cmsg->neigh_sub.sip = tcpo->tag;
	cmsg->neigh_sub.sport = tcpo->sport;
	cmsg->neigh_sub.dip = cb_in->sub.sip;
	cmsg->neigh_sub.dport = cb_in->sub.sport;
	cb_in->neigh_sub = cmsg->neigh_sub;
	cmsg->lhop = rhop;
	cmsg->rhop = rhop;

	fix_csum(newip, newtcp);

	return newpkt;
}




Packet* DyscoAgentIn::createSynReconfig(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "I'm going to create a SYN for a reconfiguration.\n");
#endif
	Packet* newpkt = Packet::Alloc();
	newpkt->set_data_off(SNBUF_HEADROOM);

	newpkt->set_data_len(pkt->data_len() + 8); //+4 for WS, +2 for NOP, +2 for SACK 
	newpkt->set_total_len(pkt->total_len() + 8); //+4 for WS, +2 for NOP, +2 for SACK
	
	uint32_t sc_len = (hasPayload(ip, tcp) - sizeof(DyscoControlMessage))/sizeof(uint32_t);
	
	DyscoHashIn* cb_in = dc->lookup_input_by_ss(this->index, &cmsg->my_sub);
	
	if(!cb_in) {
		cb_in = dc->lookup_input_by_ss(this->index, &cmsg->neigh_sub);

		if(!cb_in) {
			return 0;
		}
	}
	
	DyscoHashOut* old_dcb = cb_in->dcb_out;
	uint32_t* sc = reinterpret_cast<uint32_t*>(cmsg + 1);

	//should ARP
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->src_addr = eth->dst_addr;
	neweth->dst_addr = eth->src_addr;
	neweth->ether_type = eth->ether_type;

	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->version = 4;
	newip->header_length = 5;
	newip->type_of_service = ip->type_of_service;
	//newip->length = ip->length;
	newip->length = ip->length + be16_t(8); //+8 for TCP Options
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = be32_t(ntohl(sc[0]));

	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = be16_t(40000 + (rand() % 10000));
	newtcp->dst_port = be16_t(50000 + (rand() % 10000));
	newtcp->seq_num = be32_t(old_dcb->seq_cutoff - 1); //TEST
	//newtcp->seq_num = be32_t(old_dcb->last_seq - 1);
	newtcp->ack_num = be32_t(old_dcb->last_ack - 1);
	//newtcp->seq_num = be32_t(old_dcb->out_iseq);
	//newtcp->ack_num = be32_t(old_dcb->out_iack);
	newtcp->offset = 7; //5 + 2 for WS,NOP,SACK
	newtcp->reserved = 0;
	newtcp->flags = Tcp::kSyn;
	newtcp->window = be16_t(65535);
	newtcp->urgent_ptr = be16_t(0);

	uint8_t* ws = reinterpret_cast<uint8_t*>(newtcp + 1);
	//Window Scaling
	ws[0] = 3;   //kind 
	ws[1] = 3;   //length
	ws[2] = 14;  //multiplier
	//NOP -- for alignment
	ws[3] = 1;
	ws[4] = 1;
	ws[5] = 1;
	//SACK
	ws[6] = 4;
	ws[7] = 2;
	
	//DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
	DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(ws + 8);
	newcmsg->my_sub.sip = newip->src.raw_value();
	newcmsg->my_sub.dip = newip->dst.raw_value();
	newcmsg->my_sub.sport = newtcp->src_port.raw_value();
	newcmsg->my_sub.dport = newtcp->dst_port.raw_value();
	newcmsg->super = cmsg->leftSS;
	newcmsg->leftSS = cmsg->leftSS;
	newcmsg->rightSS = cmsg->rightSS;
	newcmsg->leftIseq = htonl(old_dcb->out_iseq);
	newcmsg->leftIack = htonl(old_dcb->out_iack);
	newcmsg->leftIts = htonl(old_dcb->ts_in);
	newcmsg->leftItsr = htonl(old_dcb->tsr_in);
	newcmsg->leftIws = htons(old_dcb->ws_in);
	newcmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);
	newcmsg->sackOk = htonl(old_dcb->sack_ok);
	newcmsg->type = DYSCO_RECONFIG;
	newcmsg->leftA = ip->dst.raw_value();
	newcmsg->rightA = cmsg->rightA;
	newcmsg->seqCutoff = htonl(old_dcb->seq_cutoff);
	newcmsg->semantic = htons(NOSTATE_TRANSFER);
	
	uint32_t* newsc = reinterpret_cast<uint32_t*>(newcmsg + 1);
	for(uint32_t i = 0; i < sc_len; i++)
		newsc[i] = sc[i];

	fix_csum(newip, newtcp);

	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cb_in->dcb_out->sup;
	rcb->sub_out.sip = newip->src.raw_value();
	rcb->sub_out.dip = newip->dst.raw_value();
	rcb->sub_out.sport = newtcp->src_port.raw_value();
	rcb->sub_out.dport = newtcp->dst_port.raw_value();
	
	rcb->leftIseq = old_dcb->out_iseq;
	rcb->leftIack = old_dcb->out_iack;
	rcb->leftIts = old_dcb->ts_in;
	rcb->leftItsr = old_dcb->tsr_in;
	rcb->leftIws = old_dcb->ws_in;
	rcb->leftIwsr = old_dcb->dcb_in->ws_in;
	rcb->sack_ok = old_dcb->sack_ok;

	if(!dc->insert_hash_reconfig(this->index, rcb))
		return 0;

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

	new_dcb->dcb_in = insert_cb_out_reverse(new_dcb, 1, newcmsg);
	dc->insert_hash_input(this->index, new_dcb->dcb_in);

	new_dcb->dcb_in->is_reconfiguration = 1;
		
	memcpy(&new_dcb->cmsg, newcmsg, sizeof(DyscoControlMessage));
	new_dcb->is_reconfiguration = 1;

	if(old_dcb->dcb_in)
		old_dcb->dcb_in->two_paths = 1;

	if(ntohs(newcmsg->semantic) == STATE_TRANSFER)
		old_dcb->state_t = 1;

	new_dcb->state = DYSCO_SYN_SENT;
	
	//LNode<Packet>* node = agent->forward(newpkt, true);
	agent->forward(newpkt, true);
	//uint32_t j = newtcp->seq_num.value() + 1;
	//mtx.lock();
	//received_hash->operator[](j) = node;
	//mtx.unlock();

	return 0;
}

bool DyscoAgentIn::createAckLockingSignalPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>((uint8_t*)tcp + 20);
	uint32_t payload_len = hasPayload(ip, tcp);
	
	pkt->trim(tcpo->len + payload_len);

	Ethernet::Address macswap = eth->src_addr;
	eth->src_addr = eth->dst_addr;
	eth->dst_addr = macswap;

	ip->header_length = 5;
	ip->length = be16_t(sizeof(Ipv4) + sizeof(Tcp));
	ip->id = be16_t(rand());
	ip->ttl = 53;
	be32_t ipswap = ip->src;
	ip->src = ip->dst;
	ip->dst = ipswap;

	be16_t portswap = tcp->src_port;
	tcp->src_port = tcp->dst_port;
	tcp->dst_port = portswap;
	be32_t toAcked = tcp->seq_num + be32_t(payload_len);
	tcp->seq_num = tcp->ack_num;
	tcp->ack_num = toAcked;
	tcp->offset = 5;
	tcp->flags = Tcp::kAck;

	fix_csum(ip, tcp);

	return true;
}




















/*
 * Locking methods
 */
Packet* DyscoAgentIn::processLockingPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp) {
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
	
	DyscoHashIn* cb_in = dc->lookup_input_by_ss(this->index, &cmsg->my_sub);
	if(!cb_in) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm looking for %s on input_hash... not found... maybe NAT?\n", printSS(cmsg->my_sub));
#endif

#ifdef DEBUG_RECONFIG
		if(cmsg->neigh_sub == cmsg->my_sub)
			fprintf(stderr, "No, there is not NAT.\n");
		else
			fprintf(stderr, "Yes, there is a NAT.\n");
#endif
		
		cb_in = dc->lookup_input_by_ss(this->index, &cmsg->neigh_sub);

		if(!cb_in) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "I'm looking for %s on input_hash... not found.\n", printSS(cmsg->neigh_sub));
#endif
			return 0;
		}
	}

	cb_in->neigh_sub = cmsg->my_sub;
	
	if(cmsg->lock_state == DYSCO_REQUEST_LOCK) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "processing Request Locking.\n");
#endif

		return processRequestLocking(pkt, eth, ip, tcp, cmsg, cb_in);
	} else if(cmsg->lock_state == DYSCO_ACK_LOCK) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "processing Ack Locking.\n");
#endif
		return processAckLocking(pkt, eth, ip, tcp, cmsg, cb_in);
	}
	
	return 0;
}

Packet* DyscoAgentIn::processRequestLocking(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out;
	
	cmsg->rhop--;
	if(cmsg->rhop > 0) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] I'm not the RightAnchor.\n", ns.c_str());
#endif
		cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
		if(!cb_out) {
			DyscoLockingReconfig* dysco_locking = dc->lookup_locking_reconfig_by_ss(this->index, &cb_in->dcb_out->sup);

			if(dysco_locking)
				cb_out = dysco_locking->cb_out_right;
		}
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] I'm the RightAnchor.\n", ns.c_str());
#endif
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][processRequestLocking] ERROR: cb_out not found... dropping.\n", ns.c_str());
#endif
		return 0;
	}
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_REQUEST_LOCK:
		//If is there another locking request with other RA?
		if(cmsg->rhop > 0) {
			eth->src_addr = cb_out->mac_sub.src_addr;
			eth->dst_addr = cb_out->mac_sub.dst_addr;
			*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
			*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
			cmsg->my_sub = cb_out->sub;
			fix_csum(ip, tcp); 
			
			cb_out->lock_state = DYSCO_REQUEST_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_REQUEST_LOCK;
			
			PacketBatch out;
			out.clear();
			out.add(pkt);
			cb_out->module->RunChooseModule(1, &out);

			return 0;
		} else {
			cb_out->is_RA = 1;
			cb_out->lock_state = DYSCO_ACK_LOCK;

			return createAckLocking(pkt, eth, ip, tcp, cmsg, cb_out);
		}
	}
	
	return 0;
}

Packet* DyscoAgentIn::processAckLocking(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out;
	
	cmsg->lhop--;
	if(cmsg->lhop > 0) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm not the LeftAnchor.\n");
#endif
		cb_out = dc->lookup_output_by_ss(this->index, &cb_in->my_sup);
		if(!cb_out) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "Looking for %s on output_hash... not found.\n", printSS(cb_in->my_sup));
#endif
			DyscoLockingReconfig* dysco_locking = dc->lookup_locking_reconfig_by_ss(this->index, &cb_in->dcb_out->sup);
			
			if(!dysco_locking) {
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "Looking for %s on lockingreconfig_hash... not found.\n", printSS(cb_in->dcb_out->sup));
#endif
			} else {
				cb_out = dysco_locking->cb_out_left;
			}
		}
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm the LeftAnchor.\n");
#endif
		cb_out = cb_in->dcb_out;
	}
			
	if(!cb_out) {
		//#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s][processAckLocking] ERROR: cb_out not found... dropping.\n", ns.c_str());
		//#endif
		return 0;
	}
	
	switch(cb_out->lock_state) {
	case DYSCO_CLOSED_LOCK:
	case DYSCO_NACK_LOCK:
	case DYSCO_ACK_LOCK:
		return 0;
		
	case DYSCO_REQUEST_LOCK:
		if(cb_out->is_LA) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "I'm the LeftAnchor... starting reconfiguration.\n\n");
#endif
			tcp->checksum++; //due cmsg->lhop--
			cb_out->lock_state = DYSCO_ACK_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_ACK_LOCK;
			
			createSynReconfig(pkt, eth, ip, tcp, cmsg);

			return 0;
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "I'm not the LeftAnchor... forwarding the DYSCO_ACK_LOCK.\n\n");
#endif	
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
					return 0;

				memcpy(sc, cb_out->sc, sc_sz);
				ip->length = ip->length + be16_t(sc_sz);
				tcp->ack_num = tcp->ack_num + be32_t(sc_sz);
#ifdef DEBUG_RECONFIG
					fprintf(stderr, "I'm going to append %d ip addresses on SYN+ACK payload.\n", cb_out->sc_len);
#endif		
				DyscoTcpSession ss;
				ss.sip = cb_in->my_sup.dip;
				ss.dip = cb_in->my_sup.sip;
				ss.sport = cb_in->my_sup.dport;
				ss.dport = cb_in->my_sup.sport;
				cmsg->rightSS = ss;
				cmsg->leftSS = cb_out->dcb_in->my_sup;
			}

			DyscoTcpSession neigh_sub = cb_out->dcb_in->neigh_sub;
			cmsg->neigh_sub.sip = neigh_sub.dip;
			cmsg->neigh_sub.dip = neigh_sub.sip;
			cmsg->neigh_sub.sport = neigh_sub.dport;
			cmsg->neigh_sub.dport = neigh_sub.sport;
			
			fix_csum(ip, tcp);
			cb_out->lock_state = DYSCO_ACK_LOCK;
			cb_in->dcb_out->lock_state = DYSCO_ACK_LOCK;

			PacketBatch out;
			out.clear();
			out.add(pkt);
			cb_out->module->RunChooseModule(1, &out);
	
			return 0;
		}
	}
	
	return 0;
}

Packet* DyscoAgentIn::createAckLocking(Packet*, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg, DyscoHashOut* cb_out) {
#ifdef DEBUG_RECONFIG
	fprintf(stderr, "I'm going to create a SYN+ACK for SYN (DYSCO_REQUEST_LOCK).\n");
#endif
	Packet* newpkt = Packet::Alloc();
	newpkt->set_data_off(SNBUF_HEADROOM);
	
	uint32_t size = sizeof(Ethernet) + sizeof(Ipv4) + sizeof(Tcp) + sizeof(DyscoControlMessage);
	
	if(cb_out->is_signaler)
		size += cb_out->sc_len * sizeof(uint32_t);

	newpkt->set_total_len(size);
	newpkt->set_data_len(size);
	
	Ethernet* neweth = newpkt->head_data<Ethernet*>();
	neweth->src_addr = eth->dst_addr;
	neweth->dst_addr = eth->src_addr;
	neweth->ether_type = eth->ether_type;

	Ipv4* newip = reinterpret_cast<Ipv4*>(neweth + 1);
	newip->header_length = 5;
	newip->version = 4;
	newip->type_of_service = 0;
	newip->length = be16_t(size - sizeof(Ethernet));
	newip->id = be16_t(rand());
	newip->fragment_offset = be16_t(0);
	newip->ttl = TTL;
	newip->protocol = Ipv4::kTcp;
	newip->src = ip->dst;
	newip->dst = ip->src;

	Tcp* newtcp = reinterpret_cast<Tcp*>(newip + 1);
	newtcp->src_port = tcp->dst_port;
	newtcp->dst_port = tcp->src_port;
	newtcp->seq_num = be32_t(rand());
	newtcp->ack_num = be32_t(tcp->seq_num.value() + hasPayload(ip, tcp) + 1);
	newtcp->reserved = 0;
	newtcp->offset = 5;
	newtcp->flags = (Tcp::kSyn|Tcp::kAck);
	newtcp->window = tcp->window;
	newtcp->urgent_ptr = be16_t(0);

	DyscoControlMessage* newcmsg = reinterpret_cast<DyscoControlMessage*>(newtcp + 1);
	newcmsg->rightA = ip->dst.raw_value();
	newcmsg->lhop = cmsg->lhop;
	newcmsg->rhop = cmsg->lhop;
	newcmsg->type = DYSCO_LOCK;
	newcmsg->lock_state = DYSCO_ACK_LOCK;
	newcmsg->my_sub.sip = cmsg->my_sub.dip;
	newcmsg->my_sub.dip = cmsg->my_sub.sip;
	newcmsg->my_sub.sport = cmsg->my_sub.dport;
	newcmsg->my_sub.dport = cmsg->my_sub.sport;
	
	if(cb_out->is_signaler) {
		uint32_t* sc = reinterpret_cast<uint32_t*>(newcmsg + 1);
		memcpy(sc, cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm going to append %u ip addresses.\n", cb_out->sc_len);
#endif
	}
	
	fix_csum(newip, newtcp);

	return newpkt;
}

ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
