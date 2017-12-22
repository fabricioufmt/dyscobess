#include "dysco_center.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../utils/format.h"
#include "dysco_policies.h"
#include "../utils/endian.h"
#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

const Commands DyscoCenter::cmds = {
	{"add", "DyscoCenterAddArg", MODULE_CMD_FUNC(&DyscoCenter::CommandAdd), Command::THREAD_UNSAFE},
	{"del", "DyscoCenterDelArg", MODULE_CMD_FUNC(&DyscoCenter::CommandDel), Command::THREAD_UNSAFE},
	{"list", "EmptyArg", MODULE_CMD_FUNC(&DyscoCenter::CommandList), Command::THREAD_UNSAFE}
};

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

DyscoCenter::DyscoCenter() : Module() {
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	uint32_t index = std::hash<std::string>()(arg.ns());
	uint32_t sc_len = arg.sc_len();
	uint32_t* sc = new uint32_t[sc_len];
	
	uint32_t i = 0;
	for(std::string s : arg.chain()) {
		inet_pton(AF_INET, s.c_str(), sc + i);
		i++;
	}
	
	DyscoHashes* dh = get_hash(index);
	if(!dh)
		return CommandFailure(ENODEV, "No hashes.");

	dh->policies.add_filter(arg.priority(), arg.filter(), sc, sc_len);
	
	bess::pb::DyscoCenterListArg l;
	l.set_msg("... Done.");	
	return CommandSuccess(l);
}

CommandResponse DyscoCenter::CommandDel(const bess::pb::DyscoCenterDelArg& arg) {
	//TODO
	fprintf(stderr, "Del: priority: %d\n", arg.priority());
	return CommandSuccess();
}

CommandResponse DyscoCenter::CommandList(const bess::pb::EmptyArg&) {
	//std::string s;
	bess::pb::DyscoCenterListArg l;

	/*for(DyscoBPF::Filter f : bpf->filters_) {
		s += std::to_string(f.priority);
		s += ": ";
		s += f.exp;
		s += "; ";
		}*/

	//l.set_msg(s);
	l.set_msg("... Done.");
	return CommandSuccess(l);
}

uint32_t DyscoCenter::get_index(const std::string& name, uint32_t ip) {
	uint32_t index = std::hash<std::string>()(name);
	hashes[index].devip = ip;
	
	return index;
}

DyscoHashes* DyscoCenter::get_hash(uint32_t i) {
	unordered_map<uint32_t, DyscoHashes>::iterator it = hashes.find(i);
	if(it != hashes.end())
		return &(*it).second;

	return 0;
}

uint16_t DyscoCenter::allocate_local_port(uint32_t) {
	return htons((rand() % 1000) + 10000);
}

uint16_t DyscoCenter::allocate_neighbor_port(uint32_t) {
	return htons((rand() % 1000) + 30000);
}

DyscoHashIn* DyscoCenter::lookup_input(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashIn, DyscoTcpSessionHash>::iterator it = dh->hash_in.begin();
	while(it != dh->hash_in.end()) {
		if(equals((*it).first, ss))
			return &(*it).second;
		it++;
	}
	
	return 0;
}

DyscoHashOut* DyscoCenter::lookup_output(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;
	
	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash>::iterator it = dh->hash_out.begin();
	while(it != dh->hash_out.end()) {
		if(equals((*it).first, ss))
			return &(*it).second;
		it++;
	}
	
	return 0;
}

DyscoHashOut* DyscoCenter::lookup_output_pending(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSessionEqualTo equals;
	unordered_map<DyscoTcpSession, DyscoHashOut, DyscoTcpSessionHash>::iterator it = dh->hash_pen.begin();
	while(it != dh->hash_pen.end()) {
		if(equals((*it).first, ss))
			return &(*it).second;
		it++;
	}

	return 0;
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

	cb_out->sc_len = sc_len - 1;
	uint32_t* sc = new uint32_t[sc_len - 1];
	memcpy(sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
	cb_out->sc = sc;
	/*
	fprintf(stderr, "cb_out (adding on hash_pen SUP):\n");
	fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
		printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
	fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
		printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));
	*/
	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*sup, *cb_out));
	//TODO: DyscoTag

	return true;
}

DyscoHashOut* DyscoCenter::insert_cb_in_reverse(DyscoTcpSession* ss_payload, Ipv4* ip, Tcp* tcp) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return 0;

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

DyscoHashIn* DyscoCenter::insert_cb_in(uint32_t i, Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_sz) {
	DyscoHashes* dh = get_hash(i);
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

	DyscoTcpSession* ss = reinterpret_cast<DyscoTcpSession*>(payload);
	memcpy(&cb_in->sup, ss, sizeof(DyscoTcpSession));

	cb_in->two_paths = 0;
	//L.218  -- dysco_input.c

	cb_in->seq_delta = cb_in->ack_delta = 0;

	cb_out = insert_cb_in_reverse(ss, ip, tcp);
	if(!cb_out) {
		delete cb_in;
		return 0;
	}
	
	if(payload_sz > sizeof(DyscoTcpSession) + sizeof(uint32_t)) {
		if(!insert_pending(dh, payload, payload_sz)) {
			delete cb_in;
			delete cb_out;
			return 0;
		}
	}
	
	cb_in->cb_out = cb_out;
	cb_out->cb_in = cb_in;
	
	dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(cb_in->sub, *cb_in));
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(cb_out->sup, *cb_out));
	
	return cb_in;
}

DyscoHashIn* DyscoCenter::insert_cb_out_reverse(uint32_t i, DyscoHashOut* cb_out, uint8_t two_paths) {
	DyscoHashes* dh = get_hash(i);
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

	cb_in->cb_out = cb_out;
	//cb_out->cb_in = cb_in; twice (below)

	dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(cb_in->sub, *cb_in));

	return cb_in;
}

bool DyscoCenter::insert_cb_out(uint32_t i, DyscoHashOut* cb_out, uint8_t two_paths) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return false;

	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(cb_out->sup, *cb_out));
	cb_out->cb_in = insert_cb_out_reverse(i, cb_out, two_paths);

	return true;
}

bool DyscoCenter::out_hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* sub) {
	if(!sub)
		return false;

	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	fix_tcp_ip_csum(ip, tcp);
	
	return true;
}

bool DyscoCenter::remove_tag(bess::Paclet*, Ipv4*, Tcp*) {
	//TODO
	//L.108 -- dysco_output.c
	//verify code.
	return true;
}

bool DyscoCenter::add_sc(bess::Packet* pkt, Ipv4* ip, DyscoHashOut* cb_out) {
	if(!cb_out)
		return false;

	uint32_t payload_sz = sizeof(DyscoTcpSession) + cb_out->sc_len * sizeof(uint32_t);
	uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));
		
	memcpy(payload, &cb_out->sup, sizeof(DyscoTcpSession));
	memcpy(payload + sizeof(DyscoTcpSession), cb_out->sc, payload_sz - sizeof(DyscoTcpSession));

	ip->length = ip->length + be16_t(payload_sz);

	return true;
}

bool DyscoCenter::fix_tcp_ip_csum(Ipv4* ip, Tcp* tcp) {
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
}

bool DyscoCenter::handle_mb_out(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return false;

	dh->hash_pen.erase(cb_out->sup);
	dh->hash_pen_tag.erase(cb_out->sup);

	if(cb_out->sc_len) {
		cb_out->sub.sip = dh->devip;
		cb_out->sub.dip = cb_out->sc[0];
	}

	cb_out->sub.sport = allocate_local_port(i);
	cb_out->sub.dport = allocate_neighbor_port(i);

	cb_out->out_iseq = cb_out->in_iseq = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);

	insert_cb_out(i, cb_out, 0);
	out_hdr_rewrite(ip, tcp, &cb_out->sub);

	if(cb_out->tag_ok)
		remove_tag(pkt, ip, tcp);

	add_sc(pkt, ip, tcp, cb_out);
	fix_tcp_ip_csum(ip, tcp);

	return true;
}

bool DyscoCenter::parse_tcp_syn_opt_s(Tcp*, DyscoHashOut*) {
	//TODO
	return true;
}

/*bool DyscoCenter::process_pending_packet(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return false;

	//fprintf(stderr, "removing hash_pen entry\n");
	dh->hash_pen.erase(*cb_out->get_sup());
	
	fprintf(stderr, "cb_out (bef--removed in hash_pen):\n");
	fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
		printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
	fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
		printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));
	
	DyscoTcpSession* sub = cb_out->get_sub();
	if(cb_out->get_sc_len()) {
		sub->sip = dh->devip;
		sub->dip = cb_out->get_sc()[0];
	}

	sub->sport = allocate_local_port(i);
	sub->dport = allocate_neighbor_port(i);

	fprintf(stderr, "cb_out (aft--removed in hash_pen):\n");
	fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
		printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
	fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
		printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));
	
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*cb_out->get_sup(), *cb_out));
	
	//TODO: parse options

	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	uint32_t payload_sz = sizeof(DyscoTcpSession) + cb_out->get_sc_len() * sizeof(uint32_t);
	uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));

	memcpy(payload, cb_out->get_sup(), sizeof(DyscoTcpSession));
	memcpy(payload + sizeof(DyscoTcpSession), cb_out->get_sc(), payload_sz - sizeof(DyscoTcpSession));

	ip->length = ip->length + be16_t(payload_sz);
	
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	DyscoHashIn* cb_in = insert_cb_out_reverse(cb_out);
	fprintf(stderr, "cb_in (reverse--adding on hash_in: SUB):\n");
	fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_in->get_sub()->sip)), ntohs(cb_in->get_sub()->sport),
		printip0(ntohl(cb_in->get_sub()->dip)), ntohs(cb_in->get_sub()->dport));
	fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_in->get_sup()->sip)), ntohs(cb_in->get_sup()->sport),
		printip0(ntohl(cb_in->get_sup()->dip)), ntohs(cb_in->get_sup()->dport));
	
	fprintf(stderr, "PRINT HASH_IN (BEF)\n");
	unordered_map<DyscoTcpSession, DyscoHashIn, DyscoTcpSessionHash>::iterator it = dh->hash_in.begin();
	while(it != dh->hash_in.end()) {
		fprintf(stderr, "(it) KEY: %s:%u -> %s:%u\n",
			printip0(ntohl((*it).first.sip)), ntohs((*it).first.sport),
			printip0(ntohl((*it).first.dip)), ntohs((*it).first.dport));
		fprintf(stderr, "(it) VAL: %s:%u -> %s:%u\n",
			printip0(ntohl((*it).second.get_sub()->sip)), ntohs((*it).second.get_sub()->sport),
			printip0(ntohl((*it).second.get_sub()->dip)), ntohs((*it).second.get_sub()->dport));
		it++;
	}
	
	//dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(*cb_in->get_sub(), *cb_in));

	DyscoTcpSessionEqualTo equals;
	it = dh->hash_in.begin();
	while(it != dh->hash_in.end()) {
		if(equals((*it).first, *cb_in->get_sub())) {
			//fprintf(stderr, "key is found... skipping.\n");
			break;
		}
		it++;
	}

	if(it == dh->hash_in.end()) {
		fprintf(stderr, "key is not found... adding OK\n");
		fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
			printip0(ntohl(cb_in->get_sub()->sip)), ntohs(cb_in->get_sub()->sport),
			printip0(ntohl(cb_in->get_sub()->dip)), ntohs(cb_in->get_sub()->dport));
		fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
			printip0(ntohl(cb_in->get_sup()->sip)), ntohs(cb_in->get_sup()->sport),
			printip0(ntohl(cb_in->get_sup()->dip)), ntohs(cb_in->get_sup()->dport));
		//dh->hash_in.insert(std::make_pair(*cb_in->get_sub(), *cb_in));
		//dh->hash_in.insert(dh->hash_in.begin(), std::pair<DyscoTcpSession, DyscoHashIn>(*cb_in->get_sub(), *cb_in));
		dh->hash_in[*cb_in->get_sub()] = *cb_in;
	}

	LIST FOR TEST
	fprintf(stderr, "PRINT HASH_IN (AFT)\n");
	it = dh->hash_in.begin();
	while(it != dh->hash_in.end()) {
		fprintf(stderr, "(it) KEY: %s:%u -> %s:%u\n",
			printip0(ntohl((*it).first.sip)), ntohs((*it).first.sport),
			printip0(ntohl((*it).first.dip)), ntohs((*it).first.dport));
		fprintf(stderr, "(it) VAL: %s:%u -> %s:%u\n",
			printip0(ntohl((*it).second.get_sub()->sip)), ntohs((*it).second.get_sub()->sport),
			printip0(ntohl((*it).second.get_sub()->dip)), ntohs((*it).second.get_sub()->dport));
		
		it++;
	}
		
	return true;
}
*/
/*DyscoHashIn* DyscoCenter::insert_cb_in_reverse2(DyscoHashOut* cb_out) {
	DyscoHashIn* cb_in = new DyscoHashIn();
	if(!cb_in)
		return 0;

	DyscoTcpSession* supI = cb_in->get_sup();
	DyscoTcpSession* supO = cb_out->get_sup();
	supI->sip = supO->dip;
	supI->dip = supO->sip;
	supI->sport = supO->dport;
	supI->dport = supO->sport;

	DyscoTcpSession* subI = cb_in->get_sub();
	DyscoTcpSession* subO = cb_out->get_sub();
	subI->sip = subO->dip;
	subI->dip = subO->sip;
	subI->sport = subO->dport;
	subI->dport = subO->sport;
	
	return cb_in;
}

DyscoHashIn* DyscoCenter::insert_cb_out_reverse(DyscoHashOut* cb_out) {
	DyscoHashIn* cb_in = new DyscoHashIn();
	if(!cb_in)
		return 0;

	DyscoTcpSession* supI = cb_in->get_sup();
	DyscoTcpSession* supO = cb_out->get_sup();
	supI->sip = supO->dip;
	supI->dip = supO->sip;
	supI->sport = supO->dport;
	supI->dport = supO->sport;

	DyscoTcpSession* subI = cb_in->get_sub();
	DyscoTcpSession* subO = cb_out->get_sub();
	subI->sip = subO->dip;
	subI->dip = subO->sip;
	subI->sport = subO->dport;
	subI->dport = subO->sport;
	
	return cb_in;
}*/

DyscoHashOut* DyscoCenter::process_syn_out(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;
	
	if(!cb_out) {
		DyscoPolicies::Filter* filter = dh->policies.match_policy(pkt);
		if(!filter)
			return 0;
		
		cb_out = new DyscoHashOut();
		if(!cb_out)
			return 0;

		insert_cb_out(i, cb_out, 0);
	}

	cb_out->seq_cutoff = tcp->seq_num.value();
	parse_tcp_syn_opt_s(tcp, cb_out);
	if(isTCPACK(tcp)) {
		DyscoTcpSession local_sub;
		DyscoHashIn* cb_in_aux;

		local_sub.sip = cb_out->sup.dip;
		local_sub.dip = cb_out->sup.sip;
		local_sub.sport = cb_out->sup.dport;
		local_sub.dport = cb_out->sup.sport;

		cb_in_aux = lookup_input(i, &local_sub);
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

		out_hdr_rewrite(ip, tcp, &cb_out->sub);
		fix_tcp_ip_csum(ip, tcp);
	}

	return cb_out;
	
	/*	
		cb_out->sc = filter->sc;
		cb_out->sc_len = filter->sc_len;

		DyscoTcpSession* sup = cb_out->get_sup();
		sup->sip = htonl(ip->src.value());
		sup->dip = htonl(ip->dst.value());
		sup->sport = htons(tcp->src_port.value());
		sup->dport = htons(tcp->dst_port.value());

		DyscoTcpSession* sub = cb_out->get_sub();
		if(filter->sc_len) {
			//fprintf(stderr, "sc != 0 (OK)\n");
			sub->sip = dh->devip;
			sub->dip = filter->sc[0];
			sub->sport = allocate_local_port(i);
			sub->dport = allocate_neighbor_port(i);
		} else {
			//fprintf(stderr, "sc == 0 (NOK)\n");
			delete cb_out;
			return 0;
		}

		uint32_t payload_sz = sizeof(DyscoTcpSession) + cb_out->get_sc_len() * sizeof(uint32_t);
		uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));
		
		memcpy(payload, cb_out->get_sup(), sizeof(DyscoTcpSession));
		memcpy(payload + sizeof(DyscoTcpSession), cb_out->get_sc(), payload_sz - sizeof(DyscoTcpSession));

		ip->length = ip->length + be16_t(payload_sz);
		
		DyscoHashIn* cb_in = insert_cb_out_reverse(cb_out);
		if(!cb_in) {
			//fprintf(stderr, "cb_in for reverse (NOK).\n");
			delete cb_out;
			return 0;
		}

		cb_out->set_cb_in(cb_in);
		cb_in->set_cb_out(cb_out);
		
		dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(*cb_in->get_sub(), *cb_in));
		dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*cb_out->get_sup(), *cb_out));

		return cb_out;
	}
	//fprintf(stderr, "dcb_out is not NULL.\n");
	//TODO: parse options

	return dcb_out;
*/
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
