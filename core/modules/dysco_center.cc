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
	bpf = new DyscoBPF();
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	//TODO
	fprintf(stderr, "[DyscoCenter](CommandAdd): priority: %d, sc_len: %d, chain:", arg.priority(), arg.sc_len());
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
/*
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

DyscoTcpSession* DyscoCenter::get_subss(Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(equals(ss, (*it).first))
			return &(*it).second.subss;
		it++;
	}
	
	return 0;
}
*/

bool DyscoCenter::add_backmapping(uint32_t i, DyscoControlBlock* block) {
	DyscoControlBlock cb;	
	DyscoTcpSession* revsupss;
	DyscoTcpSession* revsubss;

	revsupss = &cb.supss;
	revsubss = &cb.subss;
	
	revsupss->i = i;
	revsupss->sip = block->supss.dip;
	revsupss->dip = block->supss.sip;
	revsupss->sport = block->supss.dport;
	revsupss->dport = block->supss.sport;

	revsubss->i = i;
	revsubss->sip = block->subss.dip;
	revsubss->dip = block->subss.sip;
	revsubss->sport = block->subss.dport;
	revsubss->dport = block->subss.sport;

	if(map.Find(*revsubss) != nullptr)
		return false;
	
	map.Insert(*revsubss, cb);

	fprintf(stderr, "[DyscoCenter](add_backmapping)[%u]: %s:%u -> %s:%u => %s:%u -> %s:%u\n",
		i,
		printip0(ntohl(revsubss->sip)), ntohs(revsubss->sport),
		printip0(ntohl(revsubss->dip)), ntohs(revsubss->dport),
		printip0(ntohl(revsupss->sip)), ntohs(revsupss->sport),
		printip0(ntohl(revsupss->dip)), ntohs(revsupss->dport));

	
	return true;
}

DyscoTcpSession* DyscoCenter::get_supss_by_subss(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.i = i;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());
	
	auto* result = map.Find(ss);
	if(result == nullptr)
		return 0;
	
	fprintf(stderr, "[DyscoCenter](get_supss_by_subss)[%u]: (SUB) %s:%u -> %s:%u\n",
		i,
		printip0(ntohl(ss.sip)), ntohs(ss.sport),
		printip0(ntohl(ss.dip)), ntohs(ss.dport));
	
	return &result->second.supss;
	//const DyscoTcpSession& t = const_cast<DyscoTcpSession&>(ss);
	
	//auto* entry = reinterpret_cast<bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>>(submap->second).Find(t);
	//if(entry == nullptr)
	//	return 0;

	//return &entry->second.subss;
	/*
	DyscoTcpSession::EqualTo equals;
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		if(i == (*it).first) {
			bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>::iterator itt = (*it).second.begin();
			while(itt != (*it).second.end()) {
				if(equals(ss, (*itt).first))
					return &(*itt).second.subss;
				
				itt++;
				}
			std::pair<DyscoTcpSession, DyscoControlBlock>* result = (*it).second.Find(ss);
			if(result)
				return 0;
		}
		it++;
	}
	return 0;
	*/
}

DyscoTcpSession* DyscoCenter::get_subss_by_supss(uint32_t i, Ipv4* ip, Tcp* tcp) {
	fprintf(stderr, "[DyscoCenter](get_subss_by_supss)[%u]: (SUP) %s:%u -> %s:%u\n",
		i,
		printip0(ip->src.value()), tcp->src_port.value(),
		printip0(ip->dst.value()), tcp->dst_port.value());
	DyscoControlBlock* cb = get_controlblock_by_supss(i, ip, tcp);
	if(!cb)
		return &cb->subss;
	
	return 0;
}

uint32_t DyscoCenter::get_index(const std::string& name) {
	return std::hash<std::string>()(name);
}
/*
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
*/

DyscoControlBlock* DyscoCenter::get_controlblock_by_subss(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.i = i;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());

	fprintf(stderr, "[DyscoCenter](get_controlblock_by_subss)[%u]:  %s:%u -> %s:%u\n",
		i,
		printip0(ip->src.value()), tcp->src_port.value(),
		printip0(ip->dst.value()), tcp->dst_port.value());
	
	HashTable::iterator it = map.begin();
	while(it != map.end()) {
		DyscoTcpSession::EqualTo equals;
		if(equals(ss, (*it).second.subss))
			return &(*it).second;
		it++;
	}

	return 0;
}

DyscoControlBlock* DyscoCenter::get_controlblock_by_supss(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.i = i;
	ss.sip = htonl(ip->src.value());
	ss.dip = htonl(ip->dst.value());
	ss.sport = htons(tcp->src_port.value());
	ss.dport = htons(tcp->dst_port.value());

	fprintf(stderr, "[DyscoCenter](get_controlblock_by_supss)[%u]: %s:%u -> %s:%u\n",
		i,
		printip0(ip->src.value()), tcp->src_port.value(),
		printip0(ip->dst.value()), tcp->dst_port.value());
	
	HashTable::iterator it = map.begin();
	DyscoTcpSession* ss2;
	while(it != map.end()) {
		DyscoTcpSession::EqualTo equals;
		fprintf(stderr, "[DyscoCenter]: (SUB) [%u]: %s:%u -> %s:%u\n",
			i,
			printip0(ntohl(ss.sip)), ntohs(ss.sport),
			printip0(ntohl(ss.dip)), ntohs(ss.dport));

		
		fprintf(stderr, "[DyscoCenter]: (SUP) [%u] %s:%u -> %s:%u\n",
			(*it).second.supss.i,
			printip0(ntohl((*it).second.supss.sip)), ntohs((*it).second.supss.sport),
			printip0(ntohl((*it).second.supss.dip)), ntohs((*it).second.supss.dport));
		ss2 = &(*it).second.supss;
		fprintf(stderr, "%u==%u, %u==%u, %u==%u, %u==%u, %u==%u\n",
			ss.i, ss2->i, ss.sip, ss2->sip, ss.dip, ss2->dip, ss.sport, ss2->sport, ss.dport, ss2->dport);

			
		if(equals(ss, (*it).second.supss)) {
			fprintf(stderr, "------------FOUND------------\n");
			return &(*it).second;
		}
		it++;
	}

	return 0;

	
	/*std::pair<uint32_t, bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>>* ret1;

	ret1 = map.Find(i);
	if(ret1 != nullptr) {
		DyscoTcpSession::EqualTo equals;
		bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>::iterator it = ret1->second.begin();
		while(it != ret1->second.end()) {
			if(equals(ss, (*it).second.supss))
				return &(*it).second;
			it++;
		}
	}
	
	return 0;*/
}

/*
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
*/
DyscoBPF::Filter* DyscoCenter::get_filter(bess::Packet* pkt) {
	return bpf->get_filter(pkt);
}

bool DyscoCenter::add_policy_rule(uint32_t priority, std::string exp, uint8_t* sc, uint32_t sc_len) {
	return bpf->add_filter(priority, exp, sc, sc_len);
}

DyscoControlBlock* DyscoCenter::add_mapping_filter(uint32_t i, Ipv4* ip, Tcp* tcp, DyscoBPF::Filter* filter) {
	DyscoTcpSession ss;
	DyscoControlBlock cb;

	cb.supss.i = i;
	cb.supss.sip = htonl(ip->src.value());
	cb.supss.dip = htonl(ip->dst.value());
	cb.supss.sport = htons(tcp->src_port.value());
	cb.supss.dport = htons(tcp->dst_port.value());
	/*cb.supss.sip = htonl(ip->src.value());
	cb.supss.dip = htonl(ip->dst.value());
	cb.supss.sport = htons(tcp->src_port.value());
	cb.supss.dport = htons(tcp->dst_port.value());*/
	
	ss.i = i;
	if(filter->i == 0)
		ss.sip = cb.supss.sip;
	else
		ss.sip = (((uint32_t*)filter->sc)[filter->i - 1]);
	ss.dip = (((uint32_t*)filter->sc)[filter->i++]);
	ss.sport = htons((rand() % 1000 + 10000));
	ss.dport = htons((rand() % 1000 + 30000));
	cb.subss = ss;

	/*std::pair<uint32_t, bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>>* ret1;

	ret1 = map.Find(i);
	if(ret1 != nullptr)
		ret1->second.Insert(ss, cb);
	else
		return 0;
	*/
	map.Insert(ss, cb);
	//map.Insert(ss, cb);
	//bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo> hash_value(ss, cb);
	//map.Insert(i, hash_value);
	fprintf(stderr, "[DyscoCenter](add_mapping_filter) SUP => SUB\n");
	fprintf(stderr, "[DyscoCenter](add_mapping_filter)[%u]: %s:%u -> %s:%u => %s:%u -> %s:%u\n",
		i,
		printip0(ntohl(cb.supss.sip)), ntohs(cb.supss.sport),
		printip0(ntohl(cb.supss.dip)), ntohs(cb.supss.dport),
		printip0(ntohl(cb.subss.sip)), ntohs(cb.subss.sport),
		printip0(ntohl(cb.subss.dip)), ntohs(cb.subss.dport));

	//return &ret1->second.Find(ss)->second;
	return &map.Find(ss)->second;
}

/*
DyscoControlBlock* DyscoCenter::add_mapping_filter(Ipv4* ip, Tcp* tcp, DyscoBPF::Filter* filter) {
	DyscoTcpSession ss;
	DyscoControlBlock cb;

	cb.supss.sip = htonl(ip->src.value());
	cb.supss.dip = htonl(ip->dst.value());
	cb.supss.sport = htons(tcp->src_port.value());
	cb.supss.dport = htons(tcp->dst_port.value());

	if(filter->i == 0)
		ss.sip = cb.supss.sip;
	else
		ss.sip = ntohl(((uint32_t*)filter->sc)[filter->i - 1]);
	ss.sip = ntohl(((uint32_t*)filter->sc)[filter->i++]);
	ss.sport = htons((rand() % 1000 + 10000));
	ss.dport = htons((rand() % 1000 + 30000));
	cb.supss = ss;
	map.Insert(ss, cb);
     
	fprintf(stderr, "DyscoCenter(add_mapping_filter): %s:%u -> %s:%u => %s:%u -> %s:%u\n",
		printip0(ntohl(ss.sip)), ntohs(ss.sport),
		printip0(ntohl(ss.dip)), ntohs(ss.dport),
		printip0(ntohl(cb.supss.sip)), ntohs(cb.supss.sport),
		printip0(ntohl(cb.supss.dip)), ntohs(cb.supss.dport));

	return &cb;
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
		cb.nextss.dip = *((uint32_t*) (payload + sizeof(DyscoTcpSession) + sizeof(uint32_t)));
		cb.nextss.sport = htons((rand() % 1000 + 10000));
		cb.nextss.dport = htons((rand() % 1000 + 30000));
	}
	map.Insert(ss, cb);
	fprintf(stderr, "DyscoCenter(add_mapping): %s:%u -> %s:%u => %s:%u -> %s:%u\n",
		printip0(ntohl(ss.sip)), ntohs(ss.sport),
		printip0(ntohl(ss.dip)), ntohs(ss.dport),
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
*/

bool DyscoCenter::add_mapping(uint32_t i, Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_len) {
	DyscoTcpSession ss;
	DyscoControlBlock cb;

	ss.i = i;
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
		cb.nextss.dip = *((uint32_t*) (payload + sizeof(DyscoTcpSession) + sizeof(uint32_t)));
		cb.nextss.sport = htons((rand() % 1000 + 10000));
		cb.nextss.dport = htons((rand() % 1000 + 30000));
	}
	map.Insert(ss, cb);
	
	/*
	std::pair<uint32_t, bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo>>* ret1;

	ret1 = map.Find(i);
	if(ret1 != nullptr)
		ret1->second.Insert(ss, cb);
	else
		return false;
	*/
	//map.Insert(ss, cb);
	//bess::utils::CuckooMap<DyscoTcpSession, DyscoControlBlock, DyscoTcpSession::Hash, DyscoTcpSession::EqualTo> hash_value(ss, cb);
	//map.Insert(i, hash_value);
	
	fprintf(stderr, "[DyscoCenter](add_mapping)[%u]: %s:%u -> %s:%u => %s:%u -> %s:%u\n",
		i,
		printip0(ntohl(ss.sip)), ntohs(ss.sport),
		printip0(ntohl(ss.dip)), ntohs(ss.dport),
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
