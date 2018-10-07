#include "dysco_agent_out.h"

uint64_t DyscoAgentOut::timeout;

const Commands DyscoAgentOut::cmds = {
	{"setup", "DyscoAgentArg", MODULE_CMD_FUNC(&DyscoAgentOut::CommandSetup), Command::THREAD_UNSAFE}
};

void timer_worker(DyscoAgentOut* agent) {
	uint64_t now_ts;
	LNode<Packet>* aux;
	LNode<Packet>* node;
	LNode<Packet>* tail;
	LinkedList<Packet>* list = 0;
	PacketBatch batch;
	
	while(1) {
		batch.clear();
		usleep(SLEEPTIME);
		/*
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] timer_worker is working now...\n", agent->getNs());
#endif
		*/
		agent->mtx.lock();
		list = agent->getRetransmissionList();
		if(!list) {
			agent->mtx.unlock();
			continue;
		}
		/*
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "[%s] retransmission_list(%p) size: %u\n", agent->getNs(), list, list->size());
#endif
*/
		tail = list->getTail();
		now_ts = tsc_to_ns(rdtsc());
		node = list->getHead()->next;

		while(node != tail) {
			if(node->cnt == 0) {
				node->cnt++;
				//batch.add(&node->element);
				batch.add(Packet::copy(&node->element));
#ifdef DEBUG_RECONFIG
				fprintf(stderr, "cnt: %s\n", printPacket(&node->element));
#endif
				node->ts = now_ts;
			} else {
				if(node->cnt > CNTLIMIT) {
					aux = node->next;
#ifdef DEBUG_RECONFIG
					//fprintf(stderr, "[%s] I am not retransmit because CNTLIMIT\n", agent->getNs());
#endif
					//list->remove(node);
					node = aux;
					
					continue;
				}
				
				if(now_ts - node->ts > DyscoAgentOut::timeout) {
#ifdef DEBUG_RECONFIG
					fprintf(stderr, "%lu - %lu = %lu > %lu\n", now_ts, node->ts, now_ts-node->ts, DyscoAgentOut::timeout);
					fprintf(stderr, "will: %s\n", printPacket(&node->element));
#endif
					node->cnt++;
					//batch.add(&node->element);
					batch.add(Packet::copy(&node->element));
					node->ts = now_ts;
				}
			}
		
			node = node->next;
		}
		
		agent->mtx.unlock();
		
		if(batch.cnt()) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "[%s][DyscoAgentOut] is going to retransmit %u packets.\n", agent->getNs(), batch.cnt());
			agent->RunChooseModule(1, &batch);
#endif
		}
	}
}

DyscoAgentOut::DyscoAgentOut() : Module() {
	dc = 0;
	devip = 0;
	index = 0;
	timeout = DEFAULT_TIMEOUT;
	timer = 0;
	retransmission_list = new LinkedList<Packet>();
}

CommandResponse DyscoAgentOut::CommandSetup(const bess::pb::DyscoAgentArg& arg) {
	gate_idx_t igate_idx = 0;

	if(!is_active_gate<bess::IGate>(igates(), igate_idx))
		return CommandFailure(EINVAL, "ERROR: Input gate 0 is not active.");

	bess::IGate* igate = igates()[igate_idx];
	DyscoPortInc* dysco_port_inc = reinterpret_cast<DyscoPortInc*>(igate->ogates_upstream()[0]->module());
	if(!dysco_port_inc)
		return CommandFailure(EINVAL, "ERROR: DyscoPortInc is not available.");
	
	DyscoVPort* dysco_vport = reinterpret_cast<DyscoVPort*>(dysco_port_inc->port_);
	if(!dysco_vport)
		return CommandFailure(EINVAL, "ERROR: DyscoVPort is not available.");

	const auto& it1 = ModuleGraph::GetAllModules().find(DYSCOCENTER_MODULENAME);
	if(it1 == ModuleGraph::GetAllModules().end())
		return CommandFailure(EINVAL, "ERROR: DyscoCenter is not available.");

	dc = reinterpret_cast<DyscoCenter*>(it1->second);

	const auto& it2 = ModuleGraph::GetAllModules().find(arg.agent().c_str());
	if(it2 == ModuleGraph::GetAllModules().end())
		return CommandFailure(EINVAL, "ERROR: DyscoAgentIn is not available.");
	
	agent = reinterpret_cast<DyscoAgentIn*>(it2->second);
	
	port = dysco_vport;
	ns = dysco_vport->ns;
	devip = dysco_vport->devip;
	index = dc->get_index(ns, devip);
	
	return CommandSuccess();
}

void DyscoAgentOut::ProcessBatch(PacketBatch* batch) {
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
	DyscoHashOut* cb_out;

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
		if(strcmp(ns.c_str(), "/var/run/netns/RA") == 0)
			fprintf(stderr, "[%s][DyscoAgentOut] receives %s [%X:%X]\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#endif
		cb_out = dc->lookup_output(this->index, ip, tcp);
		
		if(isLockingSignalPacket(tcp)) {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's Locking Signal Packet.\n");
#endif

			if(processLockingSignalPacket(pkt, eth, ip, tcp, cb_out)) {
				forward(pkt, true);
				
				continue;
			}
		} else if(isReconfigPacketOut(ip, tcp, cb_out)) {
			//TODO verify
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "It's reconfiguration packet, should be only SYN.\n");
#endif
			if(control_output(ip, tcp)) {
				forward(pkt, true);
				//dc->add_retransmission(this->index, devip, pkt);
			
#ifdef DEBUG
				fprintf(stderr, "[%s][DyscoAgentOut-Control] forwards to Retransmission %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#endif
			}
			
			continue;
		} else if(output(pkt, ip, tcp, cb_out)) {
			out_gates[1].add(pkt);
		} else
			out_gates[0].add(pkt);

#ifdef DEBUG
		if(strcmp(ns.c_str(), "/var/run/netns/RA") == 0)
			fprintf(stderr, "[%s][DyscoAgentOut] forwards %s [%X:%X]\n\n", ns.c_str(), printPacketSS(ip, tcp), tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#endif
	}
	
	//batch->clear();
	
	RunChooseModule(0, &out_gates[0]);
	RunChooseModule(1, &out_gates[1]);
}

bool DyscoAgentOut::isReconfigPacketOut(Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(ip->src.raw_value() != devip)
		return false;
	
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
	}
		
	return false;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco codes below.
 */

//L.365
uint32_t DyscoAgentOut::out_rewrite_seq(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->seq_delta) {
		uint32_t new_seq;
		uint32_t seq = tcp->seq_num.value();

		if(cb_out->seq_add)
			new_seq = seq + cb_out->seq_delta;
		else
			new_seq = seq - cb_out->seq_delta;
		
		tcp->seq_num = be32_t(new_seq);
		
		return ChecksumIncrement32(htonl(seq), htonl(new_seq));
	}

	return 0;
}

//L.391
uint32_t DyscoAgentOut::out_rewrite_ack(Tcp* tcp, DyscoHashOut* cb_out) {
	if(cb_out->ack_delta) {
		uint32_t new_ack;
		uint32_t ack = tcp->ack_num.value();

		if(cb_out->ack_add)
			new_ack = ack + cb_out->ack_delta;
		else
			new_ack = ack - cb_out->ack_delta;

		//if(cb_out->sack_ok)
		//	dc->tcp_sack(tcp, cb_out->ack_delta, cb_out->ack_add);
		
		tcp->ack_num = be32_t(new_ack);

		return ChecksumIncrement32(htonl(ack), htonl(new_ack));
	}

	return 0;
}

//L.422
uint32_t DyscoAgentOut::out_rewrite_ts(Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out->ts_ok)
		return 0;
	
	DyscoTcpTs* ts = get_ts_option(tcp);
	if(!ts)
		return 0;

	uint32_t incremental = 0;
	uint32_t new_ts, new_tsr;
	
	if(cb_out->ts_delta) {
		if(cb_out->ts_add)
			new_ts = ntohl(ts->ts) + cb_out->ts_delta;
		else
			new_ts = ntohl(ts->ts) - cb_out->ts_delta;

		new_ts = htonl(new_ts);
		incremental += ChecksumIncrement32(ts->ts, new_ts);
		ts->ts = new_ts;
	}

	if(cb_out->tsr_delta) {
		if(cb_out->tsr_add)
			new_tsr = ntohl(ts->tsr) + cb_out->tsr_delta;
		else
			new_tsr = ntohl(ts->tsr) - cb_out->tsr_delta;

		new_tsr = htonl(new_tsr);
		incremental += ChecksumIncrement32(ts->tsr, new_tsr);
		ts->tsr = new_tsr;
	}
	
	return incremental;
}

//L.466
uint32_t DyscoAgentOut::out_rewrite_rcv_wnd(Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out->ws_ok)
		return 0;
	
	if(cb_out->ws_delta) {
		uint16_t new_win;
		uint32_t wnd = tcp->window.value();

		wnd <<= cb_out->ws_in;
		wnd >>= cb_out->ws_out;
		new_win = htons(wnd);
		new_win = ntohs(new_win);
		tcp->window = be16_t(new_win);

		return ChecksumIncrement16(htons(wnd), htons(new_win));
	}

	return 0;
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
	} else {
#ifdef DEBUG_RECONFIG
		if(strcmp(ns.c_str(), "/var/run/netns/LA") == 0 || strcmp(ns.c_str(), "/var/run/netns/RA") == 0) {
			fprintf(stderr, "[%s] pick_path_seq method\n", ns.c_str());
			fprintf(stderr, "seq=%X, cb_out->seq_cutoff=%X, !before(seq, cb_out->seq_cutoff)=%u\n", seq, cb_out->seq_cutoff, !before(seq, cb_out->seq_cutoff));
		}
#endif
		if(!before(seq, cb_out->seq_cutoff)) {
			cb = cb_out->other_path;
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "picking new path\n");
#endif
		} else {
#ifdef DEBUG_RECONFIG
			fprintf(stderr, "picking old path\n");
#endif
		}
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
#ifdef DEBUG
		fprintf(stderr, "cb_out->sup: %s -- cb_out->sub: %s\n", printSS(cb_out->sup), printSS(cb_out->sub));
		fprintf(stderr, "cb_out->valid_ack_cut: %d\n", cb_out->valid_ack_cut);
		fprintf(stderr, "cb_out->use_np_ack: %d\n", cb_out->use_np_ack);
		fprintf(stderr, "after(cb_out->ack_cutoff, ack)[%X, %X]: %d\n", cb_out->ack_cutoff, ack, after(cb_out->ack_cutoff, ack));
#endif
		if(cb_out->valid_ack_cut) {
			if(cb_out->use_np_ack) {
				cb = cb_out->other_path;
			} else {
				if(!after(cb_out->ack_cutoff, ack)) {
					if(isTCPFIN(tcp))
						cb = cb_out->other_path;
					else {
#ifdef DEBUG_RECONFIG
						fprintf(stderr, "I'm going to pick new path.\n");
#endif
						cb = cb_out->other_path;
						cb_out->ack_ctr++;
						if(cb_out->ack_ctr > 1)
							cb_out->use_np_ack = 1;
					}
				} else {
#ifdef DEBUG_RECONFIG
					fprintf(stderr, "I'm going to pick old path.\n");
#endif
				}
			}
		}
	}
	
	return cb;
}

//L.585
void DyscoAgentOut::out_translate(Packet*, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	size_t ip_hlen = ip->header_length << 2;
	size_t tcp_hlen = tcp->offset << 2;
	uint32_t seg_sz = ip->length.value() - ip_hlen - tcp_hlen;
	uint32_t seq = tcp->seq_num.value() + seg_sz;
	uint32_t ack = tcp->ack_num.value();
	
	DyscoHashOut* cb = cb_out;
	DyscoHashOut* other_path = cb_out->other_path;
	if(!other_path) {
		cb_out->last_seq = tcp->seq_num.value();
		cb_out->last_ack = tcp->ack_num.value();
		
		if(isTCPACK(tcp))
			if(cb->state == DYSCO_SYN_SENT)
				cb->state = DYSCO_ESTABLISHED;

		if(isTCPFIN(tcp))
			if(cb->state == DYSCO_ESTABLISHED)
				cb->state = DYSCO_FIN_WAIT_1;
		/*
#ifdef DEBUG_RECONFIG
		if(strcmp(ns.c_str(), "/var/run/netns/LA") == 0 || strcmp(ns.c_str(), "/var/run/netns/RA") == 0) {
			fprintf(stderr, "[%s] updating cb_out->seq_cutoff...", ns.c_str());
			fprintf(stderr, "seg_sz=%u, seq=%X, cb_out->seq_cutoff=%X, after(seq, cb_out->seq_cutoff)=%u\n", seg_sz, seq, cb_out->seq_cutoff, after(seq, cb_out->seq_cutoff));
		}
#endif
		*/
		if(seg_sz > 0) {
			if(after(seq, cb_out->seq_cutoff))
				cb_out->seq_cutoff = seq;
		} else {
			if(after(ack, cb_out->ack_cutoff))
				cb_out->ack_cutoff = ack;
		}
		
		
	} else {
		if(other_path->state == DYSCO_ESTABLISHED) {
			if(isTCPFIN(tcp))
				other_path->state = DYSCO_FIN_WAIT_1;
			
			if(seg_sz > 0) {
				cb = other_path;
			} else {
				cb = pick_path_ack(tcp, cb_out);
			}
		} else if(other_path->state == DYSCO_CLOSE_WAIT) {
			if(isTCPFIN(tcp))
				other_path->state = DYSCO_LAST_ACK;

			// assumes
			cb = other_path;

		} else if(other_path->state == DYSCO_FIN_WAIT_2) {
			if(isTCPACK(tcp))
				other_path->state = DYSCO_CLOSED;

			// assumes
			cb = other_path;

		} else if(cb_out->state == DYSCO_CLOSED) {
			//TEST
			//Should forward to other_path
			cb = other_path;
		}

		cb->last_seq = tcp->seq_num.value();
		cb->last_ack = tcp->ack_num.value();
	}
		
		/*
		if(cb_out->state == DYSCO_ESTABLISHED) {
			if(seg_sz > 0)
				cb = pick_path_seq(cb_out, seq);
			else {
				cb = pick_path_ack(tcp, cb_out);
				fprintf(stderr, "ack: %X (", tcp->ack_num.raw_value());
				if(cb == other_path)
					fprintf(stderr, "new)\n");
				else
					fprintf(stderr, "old)\n");
				fprintf(stderr, "%d\n", other_path->state);
			}
		} else if(cb_out->state == DYSCO_SYN_SENT) {
			fprintf(stderr, "SYN_SENT\n");
			if(seg_sz > 0) {
				if(dc->after(seq, cb_out->seq_cutoff))
					cb_out->seq_cutoff = seq;
			} else
				cb = pick_path_ack(tcp, cb_out);
		} else if(cb_out->state == DYSCO_SYN_RECEIVED) {
			fprintf(stderr, "SYN_RECEIVED\n");
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
		} else {
			fprintf(stderr, "and now?????\n");
		}
	}
		*/

	
	hdr_rewrite_csum(ip, tcp, &cb->sub);

	uint32_t incremental = 0;

	incremental += out_rewrite_seq(tcp, cb);
	incremental += out_rewrite_ack(tcp, cb);
	incremental += out_rewrite_ts(tcp, cb);
	incremental += out_rewrite_rcv_wnd(tcp, cb);

	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
}

//L.1395
bool DyscoAgentOut::output(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out) {
		cb_out = dc->lookup_output_pending(this->index, ip, tcp);
		if(cb_out) {
			cb_out->module = this;
			return output_mb(pkt, ip, tcp, cb_out);
		}
		
		cb_out = dc->lookup_pending_tag(this->index, tcp);
		if(cb_out) {
			cb_out->module = this;
			update_four_tuple(ip, tcp, cb_out->sup);
			
			return output_mb(pkt, ip, tcp, cb_out);
		}
	}

	if(isTCPSYN(tcp)) {
		return output_syn(pkt, ip, tcp, cb_out);
	}

	if(cb_out) {
		cb_out->module = this;
		out_translate(pkt, ip, tcp, cb_out);
		return true;
	}

	return false;
}

bool DyscoAgentOut::output_syn(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out) {
		DyscoPolicies::Filter* filter = dc->match_policy(this->index, pkt);
		if(!filter)
			return false;

		cb_out = new DyscoHashOut();
		cb_out->module = this;
		cb_out->sc = filter->sc;
		cb_out->sc_len = filter->sc_len;
	
		cb_out->sup.sip = ip->src.raw_value();
		cb_out->sup.dip = ip->dst.raw_value();
		cb_out->sup.sport = tcp->src_port.raw_value();
		cb_out->sup.dport = tcp->dst_port.raw_value();

		if(cb_out->sc_len) {
			cb_out->sub.sip = devip;
			cb_out->sub.dip = cb_out->sc[0];
			cb_out->sub.sport = dc->allocate_local_port(this->index);
			cb_out->sub.dport = dc->allocate_neighbor_port(this->index);
		}

		memcpy(&cb_out->mac_sub, pkt->head_data<Ethernet*>(), sizeof(Ethernet));
		
		if(!dc->insert_hash_output(this->index, cb_out)) {
			delete cb_out;

			return false;
		}

		cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
		dc->insert_hash_input(this->index, cb_out->dcb_in);
	}
	cb_out->module = this;
	cb_out->out_iseq = tcp->seq_num.value();
	cb_out->out_iack = tcp->ack_num.value();
	cb_out->last_seq = tcp->seq_num.value();
	cb_out->last_ack = tcp->ack_num.value();
	cb_out->seq_cutoff = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);
	
	if(isTCPACK(tcp)) {
		DyscoHashIn* cb_in_aux;
		DyscoTcpSession local_sub;

		local_sub.sip = cb_out->sub.dip;
		local_sub.dip = cb_out->sub.sip;
		local_sub.sport = cb_out->sub.dport;
		local_sub.dport = cb_out->sub.sport;

		cb_in_aux = dc->lookup_input_by_ss(this->index, &local_sub);
		if(!cb_in_aux)
			return false;

		cb_out->in_iseq = cb_out->out_iseq = tcp->seq_num.value();
		cb_out->in_iack = cb_out->out_iack = tcp->ack_num.value() - 1;
		//cb_in_aux->in_iseq = cb_in_aux->out_iseq = cb_out->out_iack;
		//cb_in_aux->in_iack = cb_in_aux->out_iack = cb_out->out_iseq;
		cb_in_aux->out_iseq = cb_out->out_iack;
		cb_in_aux->out_iack = cb_out->out_iseq;
		cb_in_aux->seq_delta = cb_in_aux->ack_delta = 0;

		if(cb_out->ts_ok) {
			cb_in_aux->ts_ok = 1;
			cb_in_aux->ts_in = cb_in_aux->ts_out = cb_out->tsr_out;
			cb_in_aux->tsr_in = cb_in_aux->tsr_out = cb_out->ts_out;
			cb_in_aux->ts_delta = cb_in_aux->tsr_delta = 0;
		} else
			cb_in_aux->ts_ok = 0;

		if(!cb_out->sack_ok)
			cb_in_aux->sack_ok = 0;

		hdr_rewrite_csum(ip, tcp, &cb_out->sub);

		cb_out->state = DYSCO_SYN_RECEIVED;
	} else {
		hdr_rewrite(ip, tcp, &cb_out->sub);
		add_sc(pkt, ip, tcp, cb_out);
		fix_csum(ip, tcp);

		cb_out->state = DYSCO_SYN_SENT;
	}

	return true;
}

bool DyscoAgentOut::output_mb(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(isTCPSYN(tcp)) {
		if(isTCPACK(tcp))
			cb_out->state = DYSCO_SYN_RECEIVED;
		else
			cb_out->state = DYSCO_SYN_SENT;
	}

	dc->remove_hash_pen(this->index, cb_out);
	
	if(cb_out->sc_len) {
		cb_out->sub.sip = devip;
		cb_out->sub.dip = cb_out->sc[0];
	}

	cb_out->sub.sport = dc->allocate_local_port(this->index);
	cb_out->sub.dport = dc->allocate_neighbor_port(this->index);

	cb_out->out_iseq = cb_out->in_iseq = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);

	if(!dc->insert_hash_output(this->index, cb_out))
		return false;

	cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
	dc->insert_hash_input(this->index, cb_out->dcb_in);
	
	hdr_rewrite(ip, tcp, &cb_out->sub);

	memcpy(&cb_out->mac_sub, pkt->head_data<Ethernet*>(), sizeof(Ethernet));

	if(cb_out->tag_ok) {
		remove_tag(pkt, ip, tcp);
	}

	add_sc(pkt, ip, tcp, cb_out);
	fix_csum(ip, tcp);

	cb_out->last_seq = tcp->seq_num.value();
	cb_out->last_ack = tcp->ack_num.value();
	
	return true;
}

void DyscoAgentOut::add_sc(Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t payload_sz;
	
	if(cb_out->is_reconfiguration == 1)
		payload_sz = sizeof(DyscoControlMessage) + cb_out->sc_len * sizeof(uint32_t) + 1;
	else
		payload_sz = 2 * sizeof(DyscoTcpSession) + cb_out->sc_len * sizeof(uint32_t);
	uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));

	if(cb_out->is_reconfiguration == 1) {
		memcpy(payload, &cb_out->cmsg, sizeof(DyscoControlMessage));
		memcpy(payload + sizeof(DyscoControlMessage), cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
		payload[payload_sz - 1] = 0xFF;		
	} else {
		DyscoTcpSession sub;
		
		sub.sip = ip->src.raw_value();
		sub.dip = ip->dst.raw_value();
		sub.sport = tcp->src_port.raw_value();
		sub.dport = tcp->dst_port.raw_value();
		
		memcpy(payload, &cb_out->sup, sizeof(DyscoTcpSession));
		memcpy(payload + sizeof(DyscoTcpSession), &sub, sizeof(DyscoTcpSession));
		memcpy(payload + 2 * sizeof(DyscoTcpSession), cb_out->sc, payload_sz - sizeof(DyscoTcpSession));
	}

	ip->length = ip->length + be16_t(payload_sz);
}

void DyscoAgentOut::remove_tag(Packet* pkt, Ipv4* ip, Tcp* tcp) {
	tcp->offset -= (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length - be16_t(DYSCO_TCP_OPTION_LEN);

	pkt->trim(DYSCO_TCP_OPTION_LEN);
}


/************************************************************************/
/************************************************************************/
/*
  Dysco codes below. Control output
*/

DyscoCbReconfig* DyscoAgentOut::insert_cb_control(Ipv4* ip, Tcp* tcp, DyscoControlMessage* cmsg) {
	DyscoCbReconfig* rcb = new DyscoCbReconfig();

	rcb->super = cmsg->super;
	rcb->sub_out.sip = ip->src.raw_value();
	rcb->sub_out.dip = ip->dst.raw_value();
	rcb->sub_out.sport = tcp->src_port.raw_value();
	rcb->sub_out.dport = tcp->dst_port.raw_value();
	
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
	cb_out->module = this;
	cb_out->sup = rcb->super;
	cb_out->sub = rcb->sub_out;

	cb_out->out_iseq = cb_out->in_iseq = rcb->leftIseq;
	cb_out->out_iack = cb_out->in_iack = rcb->leftIack;

	cb_out->ts_out = cb_out->ts_in = rcb->leftIts;
	cb_out->tsr_out = cb_out->tsr_in = rcb->leftItsr;

	cb_out->ws_out = cb_out->ws_in = rcb->leftIws;

	cb_out->sack_ok = rcb->sack_ok;

	if(!dc->insert_hash_output(this->index, cb_out)) {
		delete cb_out;
		
		return false;
	}
	
	cb_out->dcb_in = insert_cb_out_reverse(cb_out, 0);
	dc->insert_hash_input(this->index, cb_out->dcb_in);

	DyscoHashIn* cb_in = cb_out->dcb_in;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_out;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_out;

	return true;
}

bool DyscoAgentOut::control_output(Ipv4* ip, Tcp* tcp) {
	uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + (tcp->offset << 2);
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
	DyscoCbReconfig* rcb = dc->lookup_reconfig_by_ss(this->index, &cmsg->super);

	uint32_t incremental = 0;
	
	if(isFromLeftAnchor(ip, cmsg)) {
#ifdef DEBUG
		fprintf(stderr, "It's the left anchor.\n");
#endif
		
		DyscoHashOut* old_dcb;
		DyscoHashOut* new_dcb;

		if(rcb) {
			//Retransmission
			incremental += ChecksumIncrement32(cmsg->leftIseq, htonl(rcb->leftIseq));
			incremental += ChecksumIncrement32(cmsg->leftIack, htonl(rcb->leftIack));
			incremental += ChecksumIncrement32(cmsg->leftIts, htonl(rcb->leftIts));
			incremental += ChecksumIncrement32(cmsg->leftItsr, htonl(rcb->leftItsr));
			incremental += ChecksumIncrement16(cmsg->leftIws, htonl(rcb->leftIws));
			incremental += ChecksumIncrement32(cmsg->leftIwsr, htonl(rcb->leftIwsr));
			incremental += ChecksumIncrement16(cmsg->sackOk, htonl(rcb->sack_ok));

			tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);
			
			cmsg->leftIseq = htonl(rcb->leftIseq);
			cmsg->leftIack = htonl(rcb->leftIack);
			cmsg->leftIts = htonl(rcb->leftIts);
			cmsg->leftItsr = htonl(rcb->leftItsr);
			cmsg->leftIws = htons(rcb->leftIws);
			cmsg->leftIwsr = htonl(rcb->leftIwsr);
			cmsg->sackOk = htons(rcb->sack_ok);

			return true;
		}


#ifdef DEBUG
		fprintf(stderr, "Looking for %s(super) on output.\n", printSS(cmsg->super));
#endif
		
		old_dcb = dc->lookup_output_by_ss(this->index, &cmsg->super);
		if(!old_dcb) {
#ifdef DEBUG
			fprintf(stderr, "Looking for %s(leftSS) on output.\n", printSS(cmsg->leftSS));
#endif
			old_dcb = dc->lookup_output_by_ss(this->index, &cmsg->leftSS);
			if(!old_dcb) {
#ifdef DEBUG
				fprintf(stderr, "lookup output returns false\n");
#endif
				return false;
			}
		}

		/*
		  Changing TCP seq/ack values to ISN from old_dcb
		 */
		incremental += ChecksumIncrement32(tcp->seq_num.raw_value(), htonl(old_dcb->out_iseq));
		incremental += ChecksumIncrement32(tcp->ack_num.raw_value(), htonl(old_dcb->out_iack));

		incremental += ChecksumIncrement32(cmsg->leftIseq, htonl(old_dcb->out_iseq));
		incremental += ChecksumIncrement32(cmsg->leftIack, htonl(old_dcb->out_iack));
		incremental += ChecksumIncrement32(cmsg->leftIts, htonl(old_dcb->ts_in));
		incremental += ChecksumIncrement32(cmsg->leftItsr, htonl(old_dcb->tsr_in));
		incremental += ChecksumIncrement16(cmsg->leftIws, htons(old_dcb->ws_in));
		
		incremental += ChecksumIncrement16(cmsg->sackOk, htonl(old_dcb->sack_ok));

		tcp->seq_num = be32_t(old_dcb->out_iseq);
		tcp->ack_num = be32_t(old_dcb->out_iack);
		cmsg->leftIseq = htonl(old_dcb->out_iseq);
		cmsg->leftIack = htonl(old_dcb->out_iack);
		cmsg->leftIts = htonl(old_dcb->ts_in);
		cmsg->leftItsr = htonl(old_dcb->tsr_in);
		cmsg->leftIws = htons(old_dcb->ws_in);
		if(old_dcb->dcb_in) {
			incremental += ChecksumIncrement32(cmsg->leftIwsr, htonl(old_dcb->dcb_in->ws_in));
			cmsg->leftIwsr = htonl(old_dcb->dcb_in->ws_in);
		}

		cmsg->sackOk = htonl(old_dcb->sack_ok);
		
		tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);

		rcb = insert_cb_control(ip, tcp, cmsg);
		if(!rcb) {
			return false;
		}

		new_dcb = new DyscoHashOut();
		new_dcb->module = this;

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

		if(new_dcb->dcb_in) {
			new_dcb->dcb_in->is_reconfiguration = 1;
		}
		
		memcpy(&new_dcb->cmsg, cmsg, sizeof(DyscoControlMessage));
		new_dcb->is_reconfiguration = 1;

		old_dcb->old_path = 1;
		//TEST
		if(old_dcb->dcb_in)
			old_dcb->dcb_in->two_paths = 1;

		if(ntohs(cmsg->semantic) == STATE_TRANSFER)
			old_dcb->state_t = 1;

		new_dcb->state = DYSCO_SYN_SENT;

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

bool DyscoAgentOut::processLockingSignalPacket(Packet* pkt, Ethernet* eth, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!cb_out) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "There's not a entry on cb_out... dropping.\n");
#endif
		return false;
	}

	if(cb_out->lock_state != DYSCO_CLOSED_LOCK) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "Lock State: either REQUEST, ACK, or NACK... dropping.\n");
#endif
		return false;
	}

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "cb_out->sub: %s.\n", printSS(cb_out->sub));
	fprintf(stderr, "cb_out->sup: %s.\n", printSS(cb_out->sup));
	if(cb_out->dcb_in) {
		fprintf(stderr, "cb_out->dcb_in->sub: %s.\n", printSS(cb_out->dcb_in->sub));
		fprintf(stderr, "cb_out->dcb_in->sup: %s.\n", printSS(cb_out->dcb_in->my_sup));
	}
	fprintf(stderr, "State: %d.\n", cb_out->state);
	fprintf(stderr, "Lock State: %d.\n", cb_out->lock_state);
#endif
	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);
	uint32_t payload_len = hasPayload(ip, tcp);
	uint32_t sc_sz = payload_len - sizeof(DyscoControlMessage);
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
			
	cb_out->is_signaler = 1;
	cb_out->sc_len = sc_sz/sizeof(uint32_t);
	cb_out->sc = new uint32_t[cb_out->sc_len];
	memcpy(cb_out->sc, reinterpret_cast<uint32_t*>(cmsg + 1), sc_sz);

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "setting up signaler and storing service chain\n");
#endif
			
	if(isLeftAnchor(tcpo)) {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm the LeftAnchor.\n");
		fprintf(stderr, "Creating the Locking Packet.\n");
#endif
		cb_out->is_LA = 1;

		uint8_t oldRhop = cmsg->rhop;
		DyscoTcpSession oldLeftSS = cmsg->leftSS;
		DyscoTcpSession oldRightSS = cmsg->rightSS;

		ip->length = be16_t(ip->length.value() - tcpo->len - sc_sz);
		pkt->trim(tcpo->len + sc_sz);
		memcpy(tcpo, cmsg, sizeof(DyscoControlMessage));

		eth->src_addr = cb_out->mac_sub.src_addr;
		eth->dst_addr = cb_out->mac_sub.dst_addr;
				
		ip->id = be16_t(rand());
		ip->ttl = 53;
		ip->checksum = 0;
		*((uint32_t*)(&ip->src)) = cb_out->sub.sip;
		*((uint32_t*)(&ip->dst)) = cb_out->sub.dip;
				
		tcp->src_port = be16_t(rand());
		tcp->dst_port = be16_t(rand());
		tcp->seq_num = be32_t(rand());
		tcp->ack_num = be32_t(0);
		tcp->offset = 5;
		tcp->flags = Tcp::kSyn;
				
		cb_out->lock_state = DYSCO_REQUEST_LOCK;

		cmsg = reinterpret_cast<DyscoControlMessage*>(getPayload(tcp));
		cmsg->lhop = oldRhop;
		cmsg->type = DYSCO_LOCK;
		cmsg->my_sub = cb_out->sub;
		cmsg->leftSS = oldLeftSS;
		cmsg->rightSS = oldRightSS;
		cmsg->lock_state = DYSCO_REQUEST_LOCK;
				
		fix_csum(ip, tcp);
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "Forwarding to %s.\n\n", printSS(cb_out->sub));
#endif
	} else {
#ifdef DEBUG_RECONFIG
		fprintf(stderr, "I'm not the LeftAnchor.\n");
		fprintf(stderr, "Changing seq_num from %X to %X.\n", tcp->seq_num.value(), cb_out->last_seq);
		fprintf(stderr, "Changing ack_num from %X to %X.\n", tcp->ack_num.value(), cb_out->last_ack);
		fprintf(stderr, "Removing and storing the payload.\n");
		fprintf(stderr, "Forwarding to %s.\n", printSS(cb_out->sub));
		fprintf(stderr, "MAC DST: %s, MAC SRC: %s\n\n", eth->dst_addr.ToString().c_str(), eth->src_addr.ToString().c_str());
		
		
#endif

		tcp->seq_num = be32_t(cb_out->last_seq - 1);
		tcp->ack_num = be32_t(cb_out->last_ack);
		hdr_rewrite(ip, tcp, &cb_out->sub);

		pkt->trim(payload_len);
		ip->length = ip->length - be16_t(payload_len);
		tcpo->tag = cb_out->sub.dip;
		tcpo->sport = cb_out->sub.dport;
		
		fix_csum(ip, tcp);

		DyscoLockingReconfig* dysco_locking = new DyscoLockingReconfig();
		dysco_locking->cb_out_left = cb_out;
		dysco_locking->cb_out_right = dc->lookup_output_by_ss(this->index, &cmsg->rightSS);
#ifdef DEBUG_RECONFIG
		if(dysco_locking->cb_out_right)
			fprintf(stderr, "Looking output for %s... found\n", printSS(cmsg->rightSS));
		else
			fprintf(stderr, "Looking output for %s... not found\n", printSS(cmsg->rightSS));

		fprintf(stderr, "cmsg->leftSS: %s\n", printSS(cmsg->leftSS));
		fprintf(stderr, "cmsg->rightSS: %s\n", printSS(cmsg->rightSS));
#endif
		dysco_locking->leftSS = cmsg->leftSS;
		dysco_locking->rightSS = cmsg->rightSS;

		
		dc->insert_locking_reconfig(this->index, dysco_locking);
	}

#ifdef DEBUG_RECONFIG
	fprintf(stderr, "Forwarding LockingSignal with tcp->flags: %u tcp->offset: %u (seq: %X:%X]\n\n", tcp->flags, tcp->offset, tcp->seq_num.raw_value(), tcp->ack_num.raw_value());
#endif
	
	return true;	
}

bool DyscoAgentOut::forward(Packet* pkt, bool reliable) {
	if(!reliable) {
		PacketBatch out_gate;
		out_gate.clear();
		out_gate.add(pkt);
		RunChooseModule(1, &out_gate);

		return true;
	}

	mtx.lock();
	//LNode<Packet>* node = retransmission_list->insertTail(*pkt, tsc_to_ns(rdtsc()));
	LNode<Packet>* node = retransmission_list->insertTail(*Packet::copy(pkt), tsc_to_ns(rdtsc()));
	mtx.unlock();
	
	uint32_t i = getValueToAck(pkt);

	bool updated = agent->updateReceivedHash(i, node);

	if(!timer)
		timer = new thread(timer_worker, this);
	
	return updated;
}

ADD_MODULE(DyscoAgentOut, "dysco_agent_out", "processes packets outcoming from host")






