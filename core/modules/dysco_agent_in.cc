//#include <net/tcp.h>
#include <netinet/tcp.h>
#include "dysco_agent_in.h"
#include "../module_graph.h"

static inline bool before(uint32_t seq1, uint32_t seq2) {
	return (int32_t)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)


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
	
	inet_pton(AF_INET, arg.ip().c_str(), &devip);
	index = dc->get_index(arg.ns(), devip);
	ns = arg.ns();
	
	return CommandSuccess();
}

void DyscoAgentIn::ProcessBatch(bess::PacketBatch* batch) {
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
//inserting_pending function is in dysco_center.cc

//L.133
//insert_cb_in_reverse is in dysco_center.cc

//L.191
DyscoHashIn* DyscoAgentIn::insert_cb_input(uint32_t index, Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_sz) {
	return dc->insert_cb_input(index, ip, tcp, payload, payload_sz);
}

//L.258
DyscoHashIn* DyscoAgentIn::lookup_input(uint32_t index, Ipv4* ip, Tcp* tcp) {
	return dc->lookup_input(index, ip, tcp);
}

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

		if(cb_in->sack_ok)
			tcp_sack(tcp, cb_in);
		
		tcp->ack_num = be32_t(new_ack);
	}

	return true;
}

//L.384
bool DyscoAgentIn::in_rewrite_ts(Tcp* tcp, DyscoHashIn* cb_in) {
	if(!cb_in)
		return false;

	DyscoTcpTs* ts = get_ts_option(tcp);
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
		DyscoHashIn* cb_in = insert_cb_input(this->index, ip, tcp, payload, payload_sz);
		if(!cb_in)
			return false;
		
		remove_sc(pkt, ip, tcp);
		parse_tcp_syn_opt_r(tcp, cb_in);
		dc->insert_tag(this->index, pkt, ip, tcp);
		in_hdr_rewrite(ip, tcp, &cb_in->sup);
	}
	
	//debug
	fprintf(stderr, "[%s][DyscoAgentIn](end of rx_initiation_new): %s:%u -> %s:%u\n\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());

	return true;
}

//L.545
bool DyscoAgentIn::set_ack_number_out(uint32_t index, Tcp* tcp, DyscoHashIn* cb_in) {
	return dc->set_ack_number_out(index, tcp, cb_in);
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

	DyscoHashOut* cb_out = cb_in->cb_out;
	if(!cb_out)
		return false;

	if(cb_out->old_path) {
		if(cb_out->state_t) {
			if(cb_out->state == DYSCO_ESTABLISHED)
				cb_in->two_paths = false;
		} else {
			if(!after(cb_out->seq_cutoff, ack_seq)) {
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
			if(!after(cb_out->seq_cutoff, ack_seq)) {
				cb_out->use_np_seq = true;
				cb_in->two_paths = false;
			}
		}
	}

	return true;
}

//L.683
bool DyscoAgentIn::in_two_paths_data_seg(Tcp* tcp, DyscoHashIn* cb_in) {
	DyscoHashOut* cb_out = cb_in->cb_out;
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
bool DyscoAgentIn::input(bess::Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	if(!isIP(eth))
		return false;

	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	size_t ip_hlen = ip->header_length << 2;
	if(!isTCP(ip))
		return false;

	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	//debug
	/*fprintf(stderr, "[%s][DyscoAgentIn] receives %s:%u -> %s:%u\n",
		ns.c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());*/
	
	DyscoHashIn* cb_in = lookup_input(this->index, ip, tcp);
	if(!cb_in) {
		if(isTCPSYN(tcp) && hasPayload(ip, tcp)) {
			//debug
			fprintf(stderr, "[%s][DyscoAgentIn] new connection with payload\n", ns.c_str());
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
				fprintf(stderr, "[%s][DyscoAgentInc] it's retransmission of TCP SYN w payload\n", ns.c_str());
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

	//debug
	/*fprintf(stderr, "[%s]%s(OUT): %s:%u -> %s:%u\n",
		ns.c_str(), name().c_str(),
		printip1(ip->src.value()), tcp->src_port.value(),
		printip1(ip->dst.value()), tcp->dst_port.value());*/

	return true;
}











bool DyscoAgentIn::tcp_sack(Tcp*, DyscoHashIn*) {
	//L.219 -- dysco_output.c
	return true;
}



DyscoTcpTs* DyscoAgentIn::get_ts_option(Tcp* tcp) {
	return dc->get_ts_option(tcp);
}









ADD_MODULE(DyscoAgentIn, "dysco_agent_in", "processes packets incoming to host")
