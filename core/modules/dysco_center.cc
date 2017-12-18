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
	map<uint32_t, DyscoHashes>::iterator it = hashes.find(i);
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
	
	map<DyscoTcpSession, DyscoHashIn>::iterator it = dh->hash_in.find(ss);
	if(it != dh->hash_in.end())
		return &(*it).second;

	return 0;
}

DyscoHashOut* DyscoCenter::lookup_output(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;
	fprintf(stderr, "[index: %u]: lookup_output\n", i);
	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	/*
	map<DyscoTcpSession, DyscoHashOut>::iterator it = dh->hash_out.find(ss);
	if(it != dh->hash_out.end())
		return &(*it).second;
	*/
	map<DyscoTcpSession, DyscoHashOut>::iterator it = dh->hash_out.begin();
	while(it != dh->hash_out.end()) {
		fprintf(stderr, "[index: %u]: sport: %u dport: %u\n", i, ntohs((*it).first.sport), ntohs((*it).first.dport));
		DyscoTcpSession::EqualTo equals;
		if(equals((*it).first, ss))
			return &(*it).second;
		it++;
	}
	fprintf(stderr, "[index: %u]: end of lookup_output\n", i);
	return 0;
}

DyscoHashOut* DyscoCenter::lookup_output_pen(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;
	fprintf(stderr, "[index: %u]: lookup_output_pen\n", i);
	DyscoTcpSession ss;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	/*
	map<DyscoTcpSession, DyscoHashOut>::iterator it = dh->hash_pen.find(ss);
	if(it != dh->hash_pen.end())
		return &(*it).second;
	*/
	map<DyscoTcpSession, DyscoHashOut>::iterator it = dh->hash_pen.begin();
	while(it != dh->hash_pen.end()) {
		fprintf(stderr, "[index: %u]: sport: %u dport: %u\n", i, ntohs((*it).first.sport), ntohs((*it).first.dport));
		DyscoTcpSession::EqualTo equals;
		if(equals((*it).first, ss))
			return &(*it).second;
		it++;
	}
	fprintf(stderr, "[index: %u]: end of lookup_output_pen\n", i);

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

	DyscoTcpSession* sup = cb_out->get_sup();
	DyscoTcpSession* ss = reinterpret_cast<DyscoTcpSession*>(payload);

	sup->sip = ss->sip;
	sup->dip = ss->dip;
	sup->sport = ss->sport;
	sup->dport = ss->dport;

	cb_out->set_sc_len(sc_len - 1);
	uint32_t* sc = new uint32_t[sc_len - 1];
	memcpy(sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), (sc_len - 1) * sizeof(uint32_t));
	cb_out->set_sc(sc);
 
	fprintf(stderr, "cb_out (pending):\n");
	fprintf(stderr, "(SUB)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
		printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
	fprintf(stderr, "(SUP)%s:%u -> %s:%u\n",
		printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
		printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));
	
	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*sup, *cb_out));
	//TODO: DyscoTag

	return true;
}

DyscoHashOut* DyscoCenter::insert_cb_in_reverse(DyscoTcpSession* ss_payload, Ipv4* ip, Tcp* tcp) {
	DyscoHashOut* cb_out = new DyscoHashOut();
	if(!cb_out)
		return 0;

	DyscoTcpSession* sup = cb_out->get_sup();
	sup->sip = ss_payload->dip;
	sup->dip = ss_payload->sip;
	sup->sport = ss_payload->dport;
	sup->dport = ss_payload->sport;

	DyscoTcpSession* sub = cb_out->get_sub();
	sub->sip = htonl(ip->dst.value());
	sub->dip = htonl(ip->src.value());
	sub->sport = htons(tcp->dst_port.value());
	sub->dport = htons(tcp->src_port.value());
	
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

	DyscoTcpSession* sub = cb_in->get_sub();
	sub->sip = htonl(ip->src.value());
	sub->dip = htonl(ip->dst.value());
	sub->sport = htons(tcp->src_port.value());
	sub->dport = htons(tcp->dst_port.value());

	DyscoTcpSession* sup = cb_in->get_sup();
	DyscoTcpSession* ss = reinterpret_cast<DyscoTcpSession*>(payload);
	memcpy(sup, ss, sizeof(DyscoTcpSession));

	if(payload_sz > sizeof(DyscoTcpSession) + sizeof(uint32_t)) {
		if(!insert_pending(dh, payload, payload_sz)) {
			delete cb_in;
			fprintf(stderr, "[index: %u]: insert_pending is NULL\n", i);
			return 0;
		}
	} else {
		fprintf(stderr, "[index: %u]: insert_cb_in_reverse\n", i);
		cb_out = insert_cb_in_reverse(ss, ip, tcp);
		if(!cb_out) {
			delete cb_in;
			fprintf(stderr, "[index: %u]: insert_cb_in_reverse is NULL\n", i);
			return 0;
		}
		fprintf(stderr, "[index: %u]: insert_cb_in_reverse is not NULL\n", i);	
			
		cb_in->set_cb_out(cb_out);
		cb_out->set_cb_in(cb_in);
	}
	
	fprintf(stderr, "[index: %u]: insert_pending is not NULL\n", i);
	fprintf(stderr, "[index: %u] cb_in:\n", i);
	fprintf(stderr, "[index: %u]: (SUB)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(sub->sip)), ntohs(sub->sport),
		printip0(ntohl(sub->dip)), ntohs(sub->dport));
	fprintf(stderr, "[index: %u]: (SUP)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(sup->sip)), ntohs(sup->sport),
		printip0(ntohl(sup->dip)), ntohs(sup->dport));
	dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(*sub, *cb_in));

	if(cb_out) {
		fprintf(stderr, "[index: %u] cb_out:\n", i);
		fprintf(stderr, "[index: %u]: (SUB)%s:%u -> %s:%u\n",
			i,
			printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
			printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
		fprintf(stderr, "[index: %u]: (SUP)%s:%u -> %s:%u\n",
			i,
			printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
			printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));

	
		dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*sup, *cb_out));	
	}
	
	return cb_in;
	
	/*DyscoHashOut* cb_out = insert_cb_in_reverse(ss, ip, tcp);
	if(!cb_out) {
		delete cb_in;
		fprintf(stderr, "[index: %u]: insert_cb_in_reverse is NULL\n", i);
		return 0;
	}
	fprintf(stderr, "[index: %u]: insert_cb_in_reverse is not NULL\n", i);	
	if(!insert_pending(dh, payload, payload_sz)) {
			delete cb_in;
			delete cb_out;
			fprintf(stderr, "[index: %u]: insert_pending is NULL\n", i);
			return 0;
	}
	fprintf(stderr, "[index: %u]: insert_pending is not NULL\n", i);	
	cb_in->set_cb_out(cb_out);
	cb_out->set_cb_in(cb_in);

	fprintf(stderr, "[index: %u] cb_in:\n", i);
	fprintf(stderr, "[index: %u]: (SUB)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(sub->sip)), ntohs(sub->sport),
		printip0(ntohl(sub->dip)), ntohs(sub->dport));
	fprintf(stderr, "[index: %u]: (SUP)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(sup->sip)), ntohs(sup->sport),
		printip0(ntohl(sup->dip)), ntohs(sup->dport));

	fprintf(stderr, "[index: %u] cb_out:\n", i);
	fprintf(stderr, "[index: %u]: (SUB)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(cb_out->get_sub()->sip)), ntohs(cb_out->get_sub()->sport),
		printip0(ntohl(cb_out->get_sub()->dip)), ntohs(cb_out->get_sub()->dport));
	fprintf(stderr, "[index: %u]: (SUP)%s:%u -> %s:%u\n",
		i,
		printip0(ntohl(cb_out->get_sup()->sip)), ntohs(cb_out->get_sup()->sport),
		printip0(ntohl(cb_out->get_sup()->dip)), ntohs(cb_out->get_sup()->dport));

	
        dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(*sub, *cb_in));
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*sup, *cb_out));

	return cb_in;
	*/
}

bool DyscoCenter::process_pending_packet(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return false;

	dh->hash_pen.erase(*cb_out->get_sup());

	DyscoTcpSession* sub = cb_out->get_sub();
	if(cb_out->get_sc_len()) {
		sub->sip = dh->devip;
		sub->dip = cb_out->get_sc()[0];
	}

	sub->sport = allocate_local_port(i);
	sub->dport = allocate_neighbor_port(i);

	//TODO: parse options

	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	uint32_t payload_sz = sizeof(DyscoTcpSession) + cb_out->get_sc_len() * sizeof(uint32_t);
	uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));
	if(!payload)
		return false;

	memcpy(payload, cb_out->get_sup(), sizeof(DyscoTcpSession));
	memcpy(payload + sizeof(DyscoTcpSession), cb_out->get_sc(), payload_sz - sizeof(DyscoTcpSession));

	ip->length = ip->length + be16_t(payload_sz);
	
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
	tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);

	return true;
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
}

DyscoHashOut* DyscoCenter::process_syn_out(uint32_t i, bess::Packet* pkt, Ipv4* ip, Tcp* tcp, DyscoHashOut* dcb_out) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;

	fprintf(stderr, "[index: %u]: process_syn_out\n", i);
	
	if(!dcb_out) {
		fprintf(stderr, "[index: %u]: dcb_out is NULL.\n", i);
		DyscoPolicies::Filter* filter = dh->policies.match_policy(pkt);
		if(!filter) {
			fprintf(stderr, "[index: %u]: filter is NULL.\n", i);
			return 0;
		}
		fprintf(stderr, "[index: %u]: filter is not NULL.\n", i);
		DyscoHashOut* cb_out = new DyscoHashOut();
		cb_out->set_sc(filter->sc);
		cb_out->set_sc_len(filter->sc_len);

		DyscoTcpSession* sup = cb_out->get_sup();
		sup->sip = htonl(ip->src.value());
		sup->dip = htonl(ip->dst.value());
		sup->sport = htons(tcp->src_port.value());
		sup->dport = htons(tcp->dst_port.value());

		DyscoTcpSession* sub = cb_out->get_sub();
		if(filter->sc_len) {
			fprintf(stderr, "[index: %u]: filter->sc_len != 0.\n", i);
			sub->sip = dh->devip;
			sub->dip = filter->sc[0];
			sub->sport = allocate_local_port(i);
			sub->dport = allocate_neighbor_port(i);
		} else {
			fprintf(stderr, "[index: %u]: filter->sc_len == 0.\n", i);
			delete cb_out;
			return 0;
		}

		uint32_t payload_sz = sizeof(DyscoTcpSession) + cb_out->get_sc_len() * sizeof(uint32_t);
		uint8_t* payload = reinterpret_cast<uint8_t*>(pkt->append(payload_sz));
		if(!payload)
			return 0;
		
		memcpy(payload, cb_out->get_sup(), sizeof(DyscoTcpSession));
		memcpy(payload + sizeof(DyscoTcpSession), cb_out->get_sc(), payload_sz - sizeof(DyscoTcpSession));

		ip->length = ip->length + be16_t(payload_sz);
		
		DyscoHashIn* cb_in = insert_cb_out_reverse(cb_out);
		if(!cb_in) {
			fprintf(stderr, "[index: %u]: cb_in is not NULL.\n", i);
			delete cb_out;
			return 0;
		}
		fprintf(stderr, "[index: %u]: cb_in is NULL.\n", i);		
		cb_out->set_cb_in(cb_in);
		cb_in->set_cb_out(cb_out);

		dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(*sub, *cb_in));
		dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(*sup, *cb_out));

		return cb_out;
	}
	fprintf(stderr, "[index: %u]: dcb_out is not NULL.\n", i);
	//TODO: parse options

	return dcb_out;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
