#include "dysco_center.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../utils/format.h"
#include "dysco_bpf.h"

const Commands DyscoCenter::cmds = {
	{"add", "DyscoCenterAddArg", MODULE_CMD_FUNC(&DyscoCenter::CommandAdd), Command::THREAD_UNSAFE},
	{"del", "DyscoCenterDelArg", MODULE_CMD_FUNC(&DyscoCenter::CommandDel), Command::THREAD_UNSAFE},
	{"list", "EmptyArg", MODULE_CMD_FUNC(&DyscoCenter::CommandList), Command::THREAD_UNSAFE}
};


DyscoCenter::DyscoCenter() : Module() {
	bpf = new DyscoBPF();
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	//TODO
	fprintf(stderr, "[DyscoCenterAdd]: priority: %d, sc_len: %d, chain:", arg.priority(), arg.sc_len());
	for(std::string s : arg.chain())
		fprintf(stderr, " %s", s.c_str());
	fprintf(stderr, ", filter: %s\n", arg.filter().c_str());

	uint32_t i = 0;
	uint32_t sc_size = arg.sc_len() * sizeof(uint32_t);
	uint8_t* sc = (uint8_t*) malloc(sc_size);
	uint32_t a, b, c, d;
	for(std::string s : arg.chain()) {
		bess::utils::Parse(s, "%u.%u.%u.%u", &a, &b, &c, &d);
		*(sc+i) = a; *(sc+i+1) = b; *(sc+i+2) = c; *(sc+i+3) = d;
		i += 4;
	}

	bpf->add_filter(arg.priority(), arg.filter(), sc, sc_size);
	
	bess::pb::DyscoCenterListArg l;
	l.set_msg("OK.");	
	return CommandSuccess(l);
}

CommandResponse DyscoCenter::CommandDel(const bess::pb::DyscoCenterDelArg& arg) {
	//TODO
	fprintf(stderr, "Del: priority: %d\n", arg.priority());
	return CommandSuccess();
}

CommandResponse DyscoCenter::CommandList(const bess::pb::EmptyArg&) {
	std::string s;
	bess::pb::DyscoCenterListArg l;

	//s += "[DyscoCenterList]:\n";
	for(DyscoBPF::Filter f : bpf->filters_) {
		s += std::to_string(f.priority);
		s += ": ";
		s += f.exp;
		s += "; ";
	}

	l.set_msg(s);
	return CommandSuccess(l);
}

DyscoTcpSession* DyscoCenter::get_supss(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());

	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second.supss;
		it++;
	}
	
	return 0;
}

DyscoTcpSession* DyscoCenter::get_nextss(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second.nextss;
		it++;
	}
	
	return 0;
}

DyscoControlBlock* DyscoCenter::get_controlblock(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second;
		it++;
	}
	
	return 0;
}

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

DyscoControlBlock* DyscoCenter::get_controlblock_supss(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	fprintf(stderr, "DyscoCenter(get_controlblock_supss): %s:%u -> %s:%u\n",
		printip0(ip->src.value()), tcp->src_port.value(),
		printip0(ip->dst.value()), tcp->dst_port.value());
	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).second.supss)) {
			fprintf(stderr, "DyscoCenter(get_controlblock_supss): found.\n");
			return &(*it).second;
		}
		it++;
	}
	fprintf(stderr, "DyscoCenter(get_controlblock_supss): not found.\n");
	return 0;
}

DyscoBPF::Filter* DyscoCenter::get_filter(bess::Packet* pkt) {
	return bpf->get_filter(pkt);
}

bool DyscoCenter::add_policy_rule(uint32_t priority, std::string exp, uint8_t* sc, uint32_t sc_len) {
	return bpf->add_filter(priority, exp, sc, sc_len);
}

bool DyscoCenter::add_mapping(Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
	DyscoTcpSession ss;
	DyscoControlBlock cb;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	cb.subss = ss;
	memcpy(&cb.supss, (DyscoTcpSession*) payload, sizeof(DyscoTcpSession));
	
	cb.sc = 0;
	cb.sc_len = 0;
	uint32_t sc_len = payload_len - sizeof(DyscoTcpSession) - sizeof(uint32_t);
	
	if(sc_len != 0) {
		cb.sc = (uint8_t*) malloc(sc_len);
		memcpy(cb.sc, payload + sizeof(DyscoTcpSession) + sizeof(uint32_t), sc_len);
		cb.sc_len = sc_len;
		cb.nextss.sip = cb.subss.dip;
		cb.nextss.dip = *((uint32_t*) (payload + sizeof(DyscoTcpSession + sizeof(uint32_t))));
		cb.nextss.sport = htons((rand() % 1000 + 10000));
		cb.nextss.dport = htons((rand() % 1000 + 30000));
	}
	map.Insert(ss, cb);
	fprintf(stderr, "DyscoCenter(add_mapping): %s:%u -> %s:%u\n",
		printip0(ntohl(cb.supss.sip)), ntohs(cb.supss.sport),
		printip0(ntohl(cb.supss.dip)), ntohs(cb.supss.dport));
	
	//TODO: check with Ronaldo, if this is really necessary
	char buf[256];
	char ipsrc[INET_ADDRSTRLEN];
	char ipdst[INET_ADDRSTRLEN];
	struct in_addr srcip;
	struct in_addr dstip;
	srcip.s_addr = cb.supss.sip;
	dstip.s_addr = cb.supss.dip;
	inet_ntop(AF_INET, &srcip, ipsrc, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dstip, ipdst, INET_ADDRSTRLEN);
	sprintf(buf, "src host %s and dst host %s and src port %u and dst port %u",
		ipsrc, ipdst, ntohs(cb.supss.sport), ntohs(cb.supss.dport));
	//debug
	fprintf(stderr, "DyscoCenter: %s\n", buf);
	std::string exp(buf, strlen(buf));
	bpf->add_filter(0, exp, cb.sc, cb.sc_len);
	
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
