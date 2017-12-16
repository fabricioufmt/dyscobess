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
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	fprintf(stderr, "[DyscoCenter](CommandAdd): priority: %d, sc_len: %d, chain:", arg.priority(), arg.sc_len());
	/*for(std::string s : arg.chain())
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

	//bpf->add_filter(arg.priority(), arg.filter(), sc, sc_size);
	*/
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

uint32_t DyscoCenter::get_index(const std::string& name) {
	return std::hash<std::string>()(name);
}

DyscoHashes* DyscoCenter::get_hash(uint32_t i) {
	map<uint32_t, DyscoHashes>::iterator it = hashes.begin();
	while(it != hashes.end()) {
		if(i == (*it).first)
			return &(*it).second;
		it++;
	}

	return 0;
}

DyscoHashOut* DyscoCenter::insert_cb_in_reverse(DyscoHashes* dh, DyscoTcpSession* ss_payload, Ipv4* ip, Tcp* tcp) {
	if(!dh)
		return 0;

	DyscoHashOut* cb_out;
		
	cb_out = new DyscoHashOut();
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

	return cb_out;
}

DyscoHashIn* DyscoCenter::insert_cb_in(uint32_t i, Ipv4* ip, Tcp* tcp, uint8_t* payload, uint32_t payload_sz) {
	DyscoHashes* dh = get_hash(i);
	if(!dh)
		return 0;

	DyscoHashIn* cb_in;
	DyscoHashOut* cb_out;
		
	cb_in = new DyscoHashIn();
	if(!cb_in)
		return 0;
	
	cb_in->sub.sip = htonl(ip->src.value());
	cb_in->sub.dip = htonl(ip->dst.value());
	cb_in->sub.sport = htons(tcp->src_port.value());
	cb_in->sub.dport = htons(tcp->dst_port.value());

	memcpy(&cb_in->sup, reinterpret_cast<DyscoTcpSession*>(payload), sizeof(cb_in->sup));

	cb_out = insert_cb_in_reverse(dh, reinterpret_cast<DyscoTcpSession*>(payload), ip, tcp);
	if(!cb_out) {
		delete cb_in;
		return 0;
	}

	cb_in->cb_out = cb_out;
	cb_out->cb_in = cb_in;

        dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn>(cb_in->subss, cb_in));
	dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut>(cb_out->supss, cb_out));
	
	return true;
}

ADD_MODULE(DyscoCenter, "dysco_center", "Dysco center")
