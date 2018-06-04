#include "dysco_util.h"
#include "dysco_center.h"

const Commands DyscoCenter::cmds = {
	{"add", "DyscoCenterAddArg", MODULE_CMD_FUNC(&DyscoCenter::CommandAdd), Command::THREAD_UNSAFE},
	{"del", "DyscoCenterDelArg", MODULE_CMD_FUNC(&DyscoCenter::CommandDel), Command::THREAD_UNSAFE},
	{"list", "DyscoCenterListArg", MODULE_CMD_FUNC(&DyscoCenter::CommandList), Command::THREAD_UNSAFE},
};

DyscoCenter::DyscoCenter() : Module() {
}

CommandResponse DyscoCenter::CommandAdd(const bess::pb::DyscoCenterAddArg& arg) {
	string ns = arg.ns();
	uint32_t index = get_index(ns, 0);
	uint32_t sc_len = arg.sc_len();
	uint32_t* sc = new uint32_t[sc_len];
	
	uint32_t i = 0;
	for(string s : arg.chain()) {
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
	string s;
	string ns = arg.ns();
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

uint32_t DyscoCenter::get_index(string ns, uint32_t devip) {
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




/************************************************************************
 *
 * Lookup methods
 *
 ************************************************************************/
DyscoHashIn* DyscoCenter::lookup_input(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;
	
	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();

	return lookup_input_by_ss(i, &ss);
}

DyscoHashIn* DyscoCenter::lookup_input_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	/*
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash>::iterator it = dh->hash_in.find(*ss);
	if(it != dh->hash_in.end())
		return it->second;
	
	return 0;
	*/

	return dh->hash_in[*ss];
}

DyscoHashOut* DyscoCenter::lookup_output(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoTcpSession ss;

	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();
	
	return lookup_output_by_ss(i, &ss);
}

DyscoHashOut* DyscoCenter::lookup_output_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	/*
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash>::iterator it = dh->hash_out.find(*ss);
	if(it != dh->hash_out.end())
		return it->second;
	
	return 0;
	*/

	return dh->hash_out[*ss];
}

DyscoHashOut* DyscoCenter::lookup_output_pending(uint32_t i, Ipv4* ip, Tcp* tcp) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	DyscoTcpSession ss;
	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();

	return dh->hash_pen[ss];
	
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash>::iterator it = dh->hash_pen.begin();
	while(it != dh->hash_pen.end()) {
		if(ss == it->first)
			return it->second;

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
	cb_out_aux.dysco_tag = 0;
	cb_out_aux.ws_in = 0;
	cb_out_aux.ts_in = 0;
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

DyscoHashOut* DyscoCenter::lookup_pending_tag_by_tag(uint32_t i, uint32_t tag) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	/*
	unordered_map<uint32_t, DyscoHashOut*>::iterator it = dh->hash_pen_tag.find(tag);
	if(it != dh->hash_pen_tag.end())
		return it->second;
	
	return 0;
	*/

	return dh->hash_pen_tag[tag];
}


DyscoCbReconfig* DyscoCenter::lookup_reconfig_by_ss(uint32_t i, DyscoTcpSession* ss) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	/*
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo>::iterator it = dh->hash_reconfig.find(*ss);
	if(it != dh->hash_reconfig.end())
		return it->second;
	
	return 0;
	*/

	return dh->hash_reconfig[*ss];
}








/************************************************************************
 *
 *
 * HashTable methods
 *
 *
 ************************************************************************/
bool DyscoCenter::insert_hash_input(uint32_t i, DyscoHashIn* cb_in) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;
	
	return dh->hash_in.insert(std::pair<DyscoTcpSession, DyscoHashIn*>(cb_in->sub, cb_in)).second;
}

bool DyscoCenter::insert_hash_output(uint32_t i, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	return dh->hash_out.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out)).second;
}

bool DyscoCenter::insert_hash_reconfig(uint32_t i, DyscoCbReconfig* rcb) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;
	
	return dh->hash_reconfig.insert(std::pair<DyscoTcpSession, DyscoCbReconfig*>(rcb->super, rcb)).second;
}

bool DyscoCenter::insert_pending(uint32_t i, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out));
	dh->hash_pen_tag.insert(std::pair<uint32_t, DyscoHashOut*>(cb_out->dysco_tag, cb_out));

	return true;
}

bool DyscoCenter::insert_pending_reconfig(uint32_t i, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;
	
	dh->hash_pen.insert(std::pair<DyscoTcpSession, DyscoHashOut*>(cb_out->sup, cb_out));
	dh->hash_pen_tag.insert(std::pair<uint32_t, DyscoHashOut*>(cb_out->dysco_tag, cb_out));

	return true;
}

bool DyscoCenter::remove_hash_reconfig(uint32_t i, DyscoCbReconfig* rcb) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	dh->hash_reconfig.erase(rcb->super);

	return true;
}

bool DyscoCenter::remove_hash_pen(uint32_t i, DyscoHashOut* cb_out) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return false;

	dh->hash_pen.erase(cb_out->sup);
	dh->hash_pen_tag.erase(cb_out->dysco_tag);

	return true;
}






/************************************************************************
 *
 *
 * DyscoControl methods
 *
 *
 ************************************************************************/





/************************************************************************/
/************************************************************************/
/*
  Dysco methods (OUTPUT)
*/



/************************************************************************/
/************************************************************************/
/*
  Dysco methods (CONTROL INPUT)
*/


DyscoPolicies::Filter* DyscoCenter::match_policy(uint32_t i, Packet* pkt) {
	DyscoHashes* dh = get_hashes(i);
	if(!dh)
		return 0;

	return dh->policies.match_policy(pkt);
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

bool DyscoCenter::add_retransmission(uint32_t i, uint32_t devip, bess::Packet* pkt) {
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

	LNode<Packet>* node = list_r->insertTail(*pkt, tsc_to_ns(rdtsc()));
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
