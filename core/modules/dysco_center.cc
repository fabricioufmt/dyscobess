#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "dysco_center.h"
#include "dysco_policies.h"
#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/format.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

#ifdef DEBUG
char* printip0(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

char* print_ss0(DyscoTcpSession ss) {
	char* buf = (char*) malloc(1024);
	sprintf(buf, "%s:%u -> %s:%u",
		printip0(ntohl(ss.sip)), ntohs(ss.sport),
		printip0(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}
#endif

const Commands DyscoCenter::cmds = {
	{"add", "DyscoCenterAddArg", MODULE_CMD_FUNC(&DyscoCenter::CommandAdd), Command::THREAD_UNSAFE},
	{"del", "DyscoCenterDelArg", MODULE_CMD_FUNC(&DyscoCenter::CommandDel), Command::THREAD_UNSAFE},
	{"list", "DyscoCenterListArg", MODULE_CMD_FUNC(&DyscoCenter::CommandList), Command::THREAD_UNSAFE}
};

DyscoCenter::DyscoCenter() : Module() {
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	std::string ns = arg.ns();
	uint32_t index = get_index(ns, 0);
	uint32_t sc_len = arg.sc_len();
	uint32_t* sc = new uint32_t[sc_len];
	
	uint32_t i = 0;
	for(std::string s : arg.chain()) {
		inet_pton(AF_INET, s.c_str(), sc + i);
		i++;
	}

	DyscoHashes* dh = get_hashes(index);
	if(!dh) {
		dh = new DyscoHashes();
		dh->ns = arg.ns();
		dh->index = index;

		hashes.insert(std::make_pair(index, dh));
	}
	
	bess::pb::DyscoCenterListArg l;
	if(!dh->policies.add_filter(arg.priority(), arg.filter(), sc, sc_len)) {
		l.set_msg("... Failed.");

		return CommandSuccess(l);
	}
	
	l.set_msg("... Done.");	
	return CommandSuccess(l);
}

CommandResponse DyscoCenter::CommandDel(const bess::pb::DyscoCenterDelArg&) {
	return CommandSuccess();
}

CommandResponse DyscoCenter::CommandList(const bess::pb::DyscoCenterListArg& arg) {
	std::string s;
	std::string ns = arg.ns();
	bess::pb::DyscoCenterListArg l;

	DyscoHashes* dh = get_hashes(get_index(ns, 0));
	if(!dh) {
		l.set_msg("Hash not found.");
		return CommandSuccess(l);
	}
	
	for(DyscoPolicies::Filter f : dh->policies.filters_) {
		s += std::to_string(f.priority);
		s += ": ";
		s += f.exp;
		s += "; ";
	}

	l.set_msg(s);
	return CommandSuccess(l);
}

/************************************************************************/
/************************************************************************/
/*
  Control methods (internal use)
 */

uint32_t DyscoCenter::get_index(std::string ns, uint32_t devip) {
	uint32_t index = std::hash<std::string>()(ns);

	DyscoHashes* dh = get_hashes(index);
	if(!dh) {
		dh = new DyscoHashes();
		dh->ns = ns;
		dh->index = index;

		hashes.insert(std::make_pair(index, dh));
	}

	if(devip) {
		if(!dh->mutexes[devip]) {
			dh->mutexes[devip] = new mutex();
			dh->retransmission_list[devip] = new LinkedList<Packet>();
			dh->received_hash[devip] = new unordered_map<uint32_t, LNode<Packet>*>();
		}
	}
	
	return index;
}

DyscoHashes* DyscoCenter::get_hashes(uint32_t i) {
	unordered_map<uint32_t, DyscoHashes*>::iterator it = hashes.find(i);
	if(it != hashes.end())
		return (*it).second;

	return 0;
}

uint32_t DyscoCenter::get_dysco_tag(uint32_t i) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
	
	return dh->dysco_tag++;
}

//TODO: specific values for each ns (index)
uint16_t DyscoCenter::allocate_local_port(uint32_t) {
	return htons((rand() % 1000) + 10000);
}

//TODO: specific values for each ns (index)
uint16_t DyscoCenter::allocate_neighbor_port(uint32_t) {
	return htons((rand() % 1000) + 30000);
}

DyscoHashIn* DyscoCenter::lookup_input_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
#ifdef DEBUG
	fprintf(stderr, "Looking (input) for %s... ", print_ss0(*ss));
#endif
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash>::iterator it = dh->hash_in.begin();
	while(it != dh->hash_in.end()) {
		if(equals((*it).first, *ss)) {
#ifdef DEBUG
			fprintf(stderr, "found.\n");
#endif
			return (*it).second;
		}
		it++;
	}
	
#ifdef DEBUG
	fprintf(stderr, "not found.\n");
#endif
	
	return 0;
}

DyscoHashIn* DyscoCenter::lookup_input(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());

	return lookup_input_by_ss(i, &ss);
}

DyscoHashOut* DyscoCenter::lookup_output_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
#ifdef DEBUG
	fprintf(stderr, "Looking (output) for %s... ", print_ss0(*ss));
#endif
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash>::iterator it = dh->hash_out.begin();
	while(it != dh->hash_out.end()) {
		if(equals((*it).first, *ss)) {
#ifdef DEBUG
			fprintf(stderr, "found.\n");
#endif
			return (*it).second;
		}
		it++;
	}
	
#ifdef DEBUG
	fprintf(stderr, "not found.\n");
#endif
	
	return 0;
}

DyscoHashOut* DyscoCenter::lookup_output(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	return lookup_output_by_ss(i, &ss);
}

DyscoHashOut* DyscoCenter::lookup_output_pending(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash>::iterator it = dh->hash_pen.begin();
	while(it != dh->hash_pen.end()) {
		if(equals((*it).first, ss))
			return (*it).second;
		it++;
	}

	return 0;
}

DyscoCbReconfig* DyscoCenter::lookup_reconfig_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
#ifdef DEBUG
	fprintf(stderr, "Looking (reconfig) for %s... ", print_ss0(*ss));
#endif
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash>::iterator it = dh->hash_reconfig.begin();
	while(it != dh->hash_reconfig.end()) {
		if(equals((*it).first, *ss)) {
#ifdef DEBUG
			fprintf(stderr, "found.\n");
#endif
			return (*it).second;
		}
		it++;
	}

#ifdef DEBUG
	fprintf(stderr, "not found.\n");
#endif

	return 0;
}

DyscoHashOut* DyscoCenter::lookup_pending_tag_by_tag(uint32_t i, uint32_t tag) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	unordered_map<uint32_t, DyscoHashOut*>::iterator it = dh->hash_pen_tag.begin();
	while(it != dh->hash_pen_tag.end()) {
		if((*it).first == tag)
			return (*it).second;
		it++;
	}

	return 0;
}

DyscoHashOut* DyscoCenter::lookup_pending_tag(uint32_t i, Tcp* tcp) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	DyscoHashOut* cb_out;
	DyscoHashOut cb_out_aux;

	cb_out_aux.tag_ok = 0;
	cb_out_aux.sub.sip = 0;
	cb_out_aux.sub.sport = 0;
	parse_tcp_syn_opt_s(tcp, &cb_out_aux);

	if(cb_out_aux.tag_ok) {
		cb_out = lookup_pending_tag_by_tag(i, cb_out_aux.dysco_tag);
		if(cb_out) {
			cb_out->ws_ok = cb_out_aux.ws_ok;
			cb_out->ws_delta = 0;
			cb_out->ws_in = cb_out->ws_out = cb_out_aux.ws_in;

			cb_out->ts_ok = cb_out_aux.ts_ok;
			cb_out->ts_delta = 0;
			cb_out->ts_in = cb_out->ts_out = cb_out_aux.ts_in;

			cb_out->sack_ok = cb_out_aux.sack_ok;

			cb_out->tag_ok = 1;
			cb_out->dysco_tag = cb_out_aux.dysco_tag;
		}

		return cb_out;
	}
	
	return 0;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco methods (INPUT)
 */
bool DyscoCenter::insert_pending_reconfig(DyscoHashes* dh, uint8_t* payload, uint32_t payload_sz) {
	if(!dh)
		return false;

	uint32_t sc_len = (payload_sz - 1 - sizeof(DyscoControlMessage))/sizeof(uint32_t); //-1 is because 0xFF byte for reconfig tag
	if(sc_len < 2)
		return false;
	
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return false;

	DyscoTcpSession* sup = &cb_out->sup;
	DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(payload);
	DyscoTcpSession* ss = &(cmsg->super);

	sup->sip = ss->sip;
	sup->dip = ss->dip;
	sup->sport = ss->sport;
	sup->dport = ss->dport;

	cb_out->dysco_tag = dh->dysco_tag++; //TODO (verify)
	cb_out->sc_len = sc_len - 1;
	uint32_t* sc = new uint32_t[sc_len - 1];
	memcpy(sc, payload + sizeof(DyscoControlMessage) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
	cb_out->sc = sc;
	cb_out->is_reconfiguration = 1;
	memcpy(&cb_out->cmsg, cmsg, sizeof(DyscoControlMessage));

#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_pen): %s.\n", print_ss0(*sup));
#endif
	
	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(*sup, cb_out));
	dh->hash_pen_tag.insert(std::pair<uint32_t, DyscoHashOut*>(cb_out->dysco_tag, cb_out));
	//TODO: DyscoTag (verify)

	return true;
}


bool DyscoCenter::insert_pending(DyscoHashes* dh, uint8_t* payload, uint32_t payload_sz) {
	if(!dh)
		return false;

	uint32_t sc_len = (payload_sz - sizeof(DyscoTcpSession))/sizeof(uint32_t);
	if(sc_len < 2)
		return false;
	
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return false;

	DyscoTcpSession* sup = &cb_out->sup;
	DyscoTcpSession* ss = reinterpret_cast<DyscoTcpSession*>(payload);

	sup->sip = ss->sip;
	sup->dip = ss->dip;
	sup->sport = ss->sport;
	sup->dport = ss->dport;

	cb_out->dysco_tag = dh->dysco_tag++; //TODO (verify)
	cb_out->sc_len = sc_len - 1;
	uint32_t* sc = new uint32_t[sc_len - 1];
	memcpy(sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
	cb_out->sc = sc;
	cb_out->is_reconfiguration = 0;

#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_pen): %s.\n", print_ss0(*sup));
#endif
	
	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(*sup, cb_out));
	dh->hash_pen_tag.insert(std::pair<uint32_t, DyscoHashOut*>(cb_out->dysco_tag, cb_out));
	//TODO: DyscoTag (verify)

	return true;
}

DyscoHashOut* DyscoCenter::insert_cb_in_reverse(DyscoTcpSession* ss_payload, Ipv4* ip, Tcp* tcp) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return 0;

#ifdef DEBUG
	fprintf(stderr, "[DyscoCenter] insert_cb_in_reverse inserting %s:%u -> %s:%u\n",
		printip0(ntohl(ss_payload->sip)), ntohs(ss_payload->sport),
		printip0(ntohl(ss_payload->dip)), ntohs(ss_payload->dport));
#endif
	cb_out->sup.sip = ss_payload->dip;
	cb_out->sup.dip = ss_payload->sip;
	cb_out->sup.sport = ss_payload->dport;
	cb_out->sup.dport = ss_payload->sport;

	cb_out->sub.sip = htonl(ip->dst.value());
	cb_out->sub.dip = htonl(ip->src.value());
	cb_out->sub.sport = htons(tcp->dst_port.value());
	cb_out->sub.dport = htons(tcp->src_port.value());

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
	
	return cb_out;
}

DyscoHashIn* DyscoCenter::insert_cb_input(uint32_t i, Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_sz) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
	
	DyscoHashOut* cb_out = NULL;
	DyscoHashIn* cb_in = new DyscoHashIn();
	if(!cb_in)
		return 0;

	cb_in->sub.sip = htonl(ip->src.value());
	cb_in->sub.dip = htonl(ip->dst.value());
	cb_in->sub.sport = htons(tcp->src_port.value());
	cb_in->sub.dport = htons(tcp->dst_port.value());

	DyscoTcpSession* ss;
	
	if(isReconfigPacket(ip, tcp))
		ss = &(reinterpret_cast<DyscoControlMessage*>(payload))->super;
	else
		ss = reinterpret_cast<DyscoTcpSession*>(payload);
	
	memcpy(&cb_in->sup, ss, sizeof(DyscoTcpSession));

	cb_in->two_paths = 0;

	cb_in->seq_delta = cb_in->ack_delta = 0;

	cb_out = insert_cb_in_reverse(ss, ip, tcp);
	if(!cb_out) {
		delete cb_in;

		return 0;
	}
	if(!isReconfigPacket(ip, tcp)) {
		if(payload_sz > sizeof(DyscoTcpSession) + sizeof(uint32_t)) {
			if(!insert_pending(dh, payload, payload_sz)) {
				delete cb_in;
				delete cb_out;
				
				return 0;
			}
		}
	} else {
		if(payload_sz > sizeof(DyscoControlMessage) + sizeof(uint32_t)) {
			if(!insert_pending_reconfig(dh, payload, payload_sz)) {
				delete cb_in;
				delete cb_out;

				return 0;
			}
		}
	}
	
	cb_in->dcb_out = cb_out;
	cb_out->dcb_in = cb_in;

#ifdef DEBUG
	fprintf(stderr, "[DyscoCenter] Inserting (hash_in): %s\n", print_ss0(cb_in->sub));
	fprintf(stderr, "[DyscoCenter] Inserting (hash_out): %s\n", print_ss0(cb_out->sup));
#endif
	
	dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn*>(cb_in->sub, cb_in));
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out));

	return cb_in;
}

bool DyscoCenter::set_ack_number_out(uint32_t i, Tcp* tcp, DyscoHashIn* cb_in) {
	cb_in->in_iseq = cb_in->out_iseq = tcp->seq_num.value();
	cb_in->in_iack = cb_in->out_iack = tcp->ack_num.value() - 1;
	cb_in->seq_delta = cb_in->ack_delta = 0;

	DyscoTcpSession ss;
	ss.sip = cb_in->sup.dip;
	ss.dip = cb_in->sup.sip;
	ss.sport = cb_in->sup.dport;
	ss.dport = cb_in->sup.sport;

	DyscoHashOut* cb_out = lookup_output_by_ss(i, &ss);

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

/************************************************************************/
/************************************************************************/
/*
  Dysco methods (OUTPUT)
*/

DyscoHashOut* DyscoCenter::create_cb_out(uint32_t i, Ipv4* ip, Tcp* tcp, DyscoPolicies::Filter* filter, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
	
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return 0;

	cb_out->sc = filter->sc;
	cb_out->sc_len = filter->sc_len;
	
	cb_out->sup.sip = htonl(ip->src.value());
	cb_out->sup.dip = htonl(ip->dst.value());
	cb_out->sup.sport = htons(tcp->src_port.value());
	cb_out->sup.dport = htons(tcp->dst_port.value());

	if(cb_out->sc_len) {
		cb_out->sub.sip = devip;
		cb_out->sub.dip = cb_out->sc[0];
		cb_out->sub.sport = allocate_local_port(i);
		cb_out->sub.dport = allocate_neighbor_port(i);
			
		return cb_out;
	}

	delete cb_out;
	return 0;
}

bool DyscoCenter::out_tx_init(bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	if(!add_sc(pkt, ip, cb_out))
		return false;
	
	return fix_tcp_ip_csum(ip, tcp);
}

DyscoHashOut* DyscoCenter::out_syn(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
	
	if(!cb_out) {
		DyscoPolicies::Filter* filter = dh->policies.match_policy(pkt);
		if(!filter)
			return 0;
		
		cb_out = create_cb_out(i, ip, tcp, filter, devip);
		if(!cb_out)
			return 0;

		insert_cb_out(i, cb_out, 0);
	}

	cb_out->seq_cutoff = tcp->seq_num.value();

	parse_tcp_syn_opt_s(tcp, cb_out);
	if(isTCPACK(tcp)) {
		DyscoTcpSession local_sub;
		DyscoHashIn* cb_in_aux;

		local_sub.sip = cb_out->sub.dip;
		local_sub.dip = cb_out->sub.sip;
		local_sub.sport = cb_out->sub.dport;
		local_sub.dport = cb_out->sub.sport;

		cb_in_aux = lookup_input_by_ss(i, &local_sub);
		if(!cb_in_aux)
			return 0;

		cb_out->in_iseq = cb_out->out_iseq = tcp->seq_num.value();
		cb_out->in_iack = cb_out->out_iack = tcp->ack_num.value() - 1;

		cb_in_aux->in_iseq = cb_in_aux->out_iseq = cb_out->out_iack;
		cb_in_aux->in_iack = cb_in_aux->out_iack = cb_out->out_iseq;

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

		out_hdr_rewrite(pkt, ip, tcp, &cb_out->sub);
		fix_tcp_ip_csum(ip, tcp);

		return cb_out;
	} else {
		out_hdr_rewrite(pkt, ip, tcp, &cb_out->sub);
		out_tx_init(pkt, ip, tcp, cb_out);
	}

	return cb_out;
}

/*
  TCP methods
*/

bool DyscoCenter::after(uint32_t seq2, uint32_t seq1) {
	return before(seq1, seq2);
}

bool DyscoCenter::before(uint32_t seq1, uint32_t seq2) {
	return (int32_t)(seq1 - seq2) < 0;
}

DyscoTcpTs* DyscoCenter::get_ts_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP)
				return reinterpret_cast<DyscoTcpTs*>(ptr);

			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

bool DyscoCenter::tcp_sack(Tcp* tcp, uint32_t delta, uint8_t add) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_SACK) {
				if((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
				   &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {
					uint8_t* lptr = ptr;
					uint32_t blen = opsize - 2;

					while(blen > 0) {
						uint32_t* left_edge = (uint32_t*) lptr;
						uint32_t* right_edge = (uint32_t*) (lptr + 4);
						uint32_t new_ack_l, new_ack_r;
						if(add) {
							new_ack_l = htonl(ntohl(*left_edge) + delta);
							new_ack_r = htonl(ntohl(*right_edge) + delta);						
						} else {
							new_ack_l = htonl(ntohl(*left_edge) - delta);
							new_ack_r = htonl(ntohl(*right_edge) - delta);						
						}

						*left_edge = new_ack_l;
						*right_edge = new_ack_r;

						lptr += 8;
						blen -= 8;
					}
				}
			}
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return true;
}

bool DyscoCenter::parse_tcp_syn_opt_s(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_out->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			switch(opsize) {
			case TCPOPT_WINDOW:
				if(opsize == TCPOLEN_WINDOW) {
					uint8_t snd_wscale = *(uint8_t*)ptr;
					
					cb_out->ws_ok = 1;
					cb_out->ws_delta = 0;
					if (snd_wscale > 14)
						snd_wscale = 14;
					
					cb_out->ws_in = cb_out->ws_out = snd_wscale;
				}
				
				break;
				
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP) {
					if(tcp->flags & Tcp::kAck) {
						uint32_t ts, tsr;
						
						cb_out->ts_ok = 1;
						ts = (uint32_t)(*ptr);
						tsr = (uint32_t)(*(ptr + 4));
						cb_out->ts_in = cb_out->ts_out = ts;
						cb_out->tsr_in = cb_out->tsr_out = tsr;
						
						cb_out->ts_delta = cb_out->tsr_delta = 0;
					}
				}
				
				break;
				
			case TCPOPT_SACK_PERMITTED:
				if(opsize == TCPOLEN_SACK_PERMITTED)
					cb_out->sack_ok = 1;
				
				break;

			case DYSCO_TCP_OPTION:
				cb_out->tag_ok = 1;
				cb_out->dysco_tag = *(uint32_t*)ptr;
				
				break;
			}

			ptr += opsize - 2;
			len -= opsize;
		}
	}
	
	return true;
}

bool DyscoCenter::parse_tcp_syn_opt_r(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t len = (tcp->offset << 4) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_in->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			switch(opsize) {
			case TCPOPT_WINDOW:
				if(opsize == TCPOLEN_WINDOW) {
					uint8_t snd_wscale = *(uint8_t*)ptr;
					
					cb_in->ws_ok = 1;
					cb_in->ws_delta = 0;
					if (snd_wscale > 14)
						snd_wscale = 14;
					
					cb_in->ws_in = cb_in->ws_out = snd_wscale;
				}
				
				break;
				
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP) {
					if(tcp->flags & Tcp::kAck) {
						uint32_t ts, tsr;
						
						cb_in->ts_ok = 1;
						ts = (uint32_t)(*ptr);
						tsr = (uint32_t)(*(ptr + 4));
						cb_in->ts_in = cb_in->ts_out = ts;
						cb_in->tsr_in = cb_in->tsr_out = tsr;
						
						cb_in->ts_delta = cb_in->tsr_delta = 0;
					}
				}
				
				break;
				
			case TCPOPT_SACK_PERMITTED:
				if(opsize == TCPOLEN_SACK_PERMITTED)
					cb_in->sack_ok = 1;
				
				break;

			ptr += opsize - 2;
			len -= opsize;
			}
		}
	}
	
	return true;
}

bool DyscoCenter::fix_tcp_ip_csum(Ipv4* ip, Tcp* tcp) {
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
}

/*
  Dysco methods
 */
bool DyscoCenter::out_handle_mb(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	dh->hash_pen.erase(cb_out->sup);
	dh->hash_pen_tag.erase(cb_out->dysco_tag);

	if(cb_out->sc_len) {
		cb_out->sub.sip = devip;
		cb_out->sub.dip = cb_out->sc[0];
	}

	cb_out->sub.sport = allocate_local_port(i);
	cb_out->sub.dport = allocate_neighbor_port(i);

	cb_out->out_iseq = cb_out->in_iseq = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);

	insert_cb_out(i, cb_out, 0);
	out_hdr_rewrite(pkt, ip, tcp, &cb_out->sub);

	//TODO: verify why cb_out->tag_ok always false
	if(cb_out->tag_ok) {
#ifdef DEBUG
		fprintf(stderr, "[DyscoCenter] handle_mb_out method, tag_ok is true\n");
#endif
		remove_tag(pkt, ip, tcp);
	} else
#ifdef DEBUG
		fprintf(stderr, "[DyscoCenter] handle_mb_out method, tag_ok is false\n");
#endif
	if(cb_out->is_reconfiguration) {
#ifdef DEBUG
		fprintf(stderr, "[DyscoCenter] cb_out is reconfiguration\n");
#endif		
		//remove_tag(pkt, ip, tcp);
	} else {
#ifdef DEBUG
		fprintf(stderr, "[DyscoCenter] cb_out is not reconfiguration and calling remove_tag\n");
#endif		
		remove_tag(pkt, ip, tcp);
	}

	add_sc(pkt, ip, cb_out);
	fix_tcp_ip_csum(ip, tcp);

	return true;
}

bool DyscoCenter::insert_tag(uint32_t index, bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	uint32_t tag = get_dysco_tag(index);
	DyscoTcpOption* dopt = reinterpret_cast<DyscoTcpOption*>(pkt->append(DYSCO_TCP_OPTION_LEN));
	dopt->kind = DYSCO_TCP_OPTION;
	dopt->len = DYSCO_TCP_OPTION_LEN;
	dopt->padding = 0;
	dopt->tag = tag;

	tcp->offset += (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length + be16_t(DYSCO_TCP_OPTION_LEN);
	
	return true;
}

bool DyscoCenter::insert_cb_out(uint32_t i, DyscoHashOut* cb_out, uint8_t two_paths) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_out): %s.\n", print_ss0(cb_out->sup));
#endif
	
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out));
	cb_out->dcb_in = insert_cb_out_reverse(i, cb_out, two_paths);

	return true;
}

DyscoHashIn* DyscoCenter::insert_cb_out_reverse(uint32_t i, DyscoHashOut* cb_out, uint8_t two_paths, DyscoControlMessage* cmsg) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;
	
	DyscoHashIn* cb_in = new DyscoHashIn();
	if(!cb_in)
		return 0;

	cb_in->sub.sip = cb_out->sub.dip;
	cb_in->sub.dip = cb_out->sub.sip;
	cb_in->sub.sport = cb_out->sub.dport;
	cb_in->sub.dport = cb_out->sub.sport;

	cb_in->sup.sip = cb_out->sup.dip;
	cb_in->sup.dip = cb_out->sup.sip;
	cb_in->sup.sport = cb_out->sup.dport;
	cb_in->sup.dport = cb_out->sup.sport;

	cb_in->in_iack = cb_in->out_iack = cb_out->out_iseq;
	cb_in->in_iseq = cb_in->out_iseq = cb_out->out_iack;

	cb_in->seq_delta = cb_in->ack_delta = 0;
	cb_in->ts_ok = cb_out->ts_ok;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_in;
	cb_in->ts_delta = 0;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_in;
	cb_in->tsr_delta = 0;
	cb_in->ws_ok = cb_out->ws_ok;
	cb_in->ws_in = cb_in->ws_out = cb_out->ws_in;
	cb_in->ws_delta = 0;
	cb_in->sack_ok = cb_out->sack_ok;
	cb_in->two_paths = two_paths;

	if(cmsg)
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));
	
	cb_in->dcb_out = cb_out;
	cb_out->dcb_in = cb_in;

#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_in): %s.\n", print_ss0(cb_in->sub));
#endif
	dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn*>(cb_in->sub, cb_in));
	
	return cb_in;
}


bool DyscoCenter::out_hdr_rewrite(bess::Packet*, Ipv4* ip, Tcp* tcp, DyscoTcpSession* sub) {
	if(!sub)
		return false;

	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	return true;
}

bool DyscoCenter::remove_tag(bess::Packet* pkt, Ipv4* ip, Tcp* tcp) {
	tcp->offset -= (DYSCO_TCP_OPTION_LEN >> 2);
	ip->length = ip->length - be16_t(DYSCO_TCP_OPTION_LEN);

	pkt->trim(DYSCO_TCP_OPTION_LEN);
	
	return true;
}

bool DyscoCenter::add_sc(bess::Packet* pkt, Ipv4* ip, DyscoHashOut* cb_out) {
	if(!cb_out)
		return false;

	uint32_t payload_sz;
	if(cb_out->is_reconfiguration == 1)  {
		payload_sz = sizeof(DyscoControlMessage) + cb_out->sc_len * sizeof(uint32_t) + 1;
	} else {
		payload_sz = sizeof(DyscoTcpSession) + cb_out->sc_len * sizeof(uint32_t);
	}
	
	uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));

	if(cb_out->is_reconfiguration == 1) {
		memcpy(payload, &cb_out->cmsg, sizeof(DyscoControlMessage));
		memcpy(payload + sizeof(DyscoControlMessage), cb_out->sc, cb_out->sc_len * sizeof(uint32_t));
		payload[payload_sz - 1] = 0xFF;		
	} else {
		memcpy(payload, &cb_out->sup, sizeof(DyscoTcpSession));
		memcpy(payload + sizeof(DyscoTcpSession), cb_out->sc, payload_sz - sizeof(DyscoTcpSession));
	}

	ip->length = be16_t(ip->length.value() + payload_sz);
	return true;
}

/************************************************************************/
/************************************************************************/
/*
  Dysco methods (CONTROL INPUT)
*/
bool DyscoCenter::insert_hash_input(uint32_t i, DyscoHashIn* cb_in) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;
#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_in): %s.\n", print_ss0(cb_in->sub));
#endif
	
	return dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn*>(cb_in->sub, cb_in)).second;
}

bool DyscoCenter::insert_hash_output(uint32_t i, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_out): %s.\n", print_ss0(cb_out->sup));
#endif
	
	return dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out)).second;
}

bool DyscoCenter::insert_hash_reconfig(uint32_t i, DyscoCbReconfig* rcb) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;
#ifdef DEBUG
	fprintf(stderr, "Inserting (hash_reconfig): %s.\n", print_ss0(rcb->super));
#endif
	
	return dh->hash_reconfig.insert(std::pair<DyscoTcpSession, DyscoCbReconfig*>(rcb->super, rcb)).second;
}

bool DyscoCenter::remove_reconfig(uint32_t i, DyscoCbReconfig* rcb) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	dh->hash_reconfig.erase(rcb->super);

	return true;
}

bool DyscoCenter::replace_cb_leftA(DyscoCbReconfig* rcb, DyscoControlMessage* cmsg) {
	DyscoHashOut* old_dcb = rcb->old_dcb;

	if(old_dcb->state == DYSCO_SYN_SENT)
		old_dcb->state = DYSCO_ESTABLISHED;

	cmsg->seqCutoff = old_dcb->seq_cutoff;

	return true;
}


/*
  TCP Retransmission methods
 */
mutex* DyscoCenter::getMutex(uint32_t i, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return nullptr;

	return dh->mutexes[devip];
}

bool DyscoCenter::addToRetransmission(uint32_t i, uint32_t devip, bess::Packet* pkt) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	mutex* mtx = getMutex(i, devip);
	if(!mtx)
		return false;

	mtx->lock();
	
	LinkedList<Packet>* list_r = dh->retransmission_list[devip];
	unordered_map<uint32_t, LNode<Packet>*>* hash_r = dh->received_hash[devip];
	if(!list_r || !hash_r) {
		mtx->unlock();
		
		return false;
	}

	LNode<Packet>* node = list_r->insertTail(*pkt);
	uint32_t index = getValueToAck(pkt);
	hash_r->operator[](index) = node;
	
	mtx->unlock();
	
	return true;
}

LinkedList<Packet>* DyscoCenter::getRetransmissionList(uint32_t i, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return nullptr;

	return dh->retransmission_list[devip];
}

unordered_map<uint32_t, LNode<Packet>*>* DyscoCenter::getHashReceived(uint32_t i, uint32_t devip) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return nullptr;

	return dh->received_hash[devip];
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
