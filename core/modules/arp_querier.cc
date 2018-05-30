#include "arp_querier.h"

void ArpQuerier::ProcessBatch(bess::PacketBatch* batch) {
	gate_idx_t incoming_gate = get_igate();

	if(incoming_gate == 0) {
		//Should be IP datagram
		ProcessBatchIP(batch);
	} else {
		//Should be ARP reply
		ProcessBatchArp(batch);
	}
}

void ArpQuerier::ProcessBatchIP(bess::PacketBatch* batch) {
	bess::PacketBatch out_batch;
	
	out_batch.clear();
	
	Ipv4* ip;
	Ethernet* eth;
	bess::Packet* pkt;
	bess::Packet* arp_created;
	
	for (int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet *>();
		ip = reinterpret_cast<Ipv4*>(eth + 1);
		
		updateSrcEthEntry(eth, ip);

		arp_created = updateDst(pkt, eth, ip);
		out_batch.add(arp_created ? arp_created : pkt);
	}

	RunChooseModule(0, &out_batch);
}

void ArpQuerier::ProcessBatchArp(bess::PacketBatch* batch) {
	Arp* arp;
	Ethernet* eth;
	bess::Packet* pkt;
	
	for (int i = 0; i < batch->cnt(); i++) {
		pkt = batch->pkts()[i];
		eth = pkt->head_data<Ethernet*>();
		arp = reinterpret_cast<Arp*>(eth + 1);
		
		updateArpEntry(eth, arp, batch);
	}

	RunChooseModule(0, batch);
}

void ArpQuerier::updateArpEntry(Ethernet* eth, Arp* arp, bess::PacketBatch* batch) {
	Arp_Entry* entry;
	Ethernet* pkt_eth;
	bess::Packet* pkt;
	be32_t ip = arp->target_ip_addr;
	Ethernet::Address mac = arp->target_hw_addr;

	auto it = entries_.find(ip);
	if(it != entries_.end()) {
		entry = &it->second;

		entry->mac = mac;

		auto itt = entry->pkts.iterator();
		while(itt != entry->pkts.end()) {
			pkt = itt->second;
			pkt_eth = pkt->head_data<Ethernet*>();

			pkt_eth->dst_addr = mac;
			batch->add(pkt);

			itt++;
		}

		entry->pkts.clear();
	} else {
		entry = new Arp_Entry();
		entry->mac = mac;
		entries_[ip] = *entry;
	}

	ip = arp->sender_ip_addr;
	mac = arp->sender_hw_addr;

	it = entries_.find(ip);
	if(it != entries_end()) {
		entry = &it->second;

		entry->mac = mac;
	} else {
		entry = new Arp_Entry();
		entry->mac = mac;
		entries_[ip] = *entry;
	}
}

void ArpQuerier::updateSrcEthEntry(Ethernet* eth, Ipv4* ip) {
	Arp_Entry* entry;
	be32_t ip = ip->src;
	Ethernet::Address mac = eth->src_addr;

	auto it = entries_.find(ip);
	if(it != entries_end()) {
		entry = &it->second;

		entry->mac = mac;
	} else {
		entry = new Arp_Entry();
		entry->mac = mac;
		entries_[ip] = *entry;
	}
}

bess::Packet* ArpQuerier::updateDst(bess::Packet* pkt, Ethernet* eth, Ipv4* ip) {
	Arp_Entry* entry;
	be32_t ip = ip->src;
	
	auto it = entries_.find(ip);
	if(it != entries_end()) {
		entry = it->second;

		if(entry->sent_request) {
			entry->pkts.add(pkt);
			return 0;
		}
		
		eth->dst_addr = entry->mac;
		
		return 0;
	}

	entry = new Arp_Entry();
	entries_[ip] = *entry;
	entry->sent_request = true;
	entry->pkts.add(pkt);

	return createArpRequest(eth, ip);
}

bess::Packet* ArpQuerier::createArpRequest(Ethernet* eth, Ipv4* ip) {
	bess::Packet* pkt = bess::Packet::Alloc();

	Ethernet* pkt_eth = pkt->head_data<Ethernet*>();
	arp_eth->ether_type = be16_t(Ethernet::Type::kArp);
	arp_eth->src_addr = eth->src_addr;
	arp_eth->dst_addr.FromString("FF:FF:FF:FF:FF:FF");

	Arp *pkt_arp = reinterpret_cast<Arp*>(pkt_eth + 1);
	pkt_arp->hw_addr = be16_t(Arp::kEthernet);
	pkt_arp->proto_addr = be16_t(Ethernet::kIpv4);
	pkt_arp->hw_addr_length = 6;
	pkt_arp->proto_addr_length = 4;
	pkt_arp->opcode = be16_t(Arp::kRequest);

	pkt_arp->sender_hw_addr = eth->src_addr;
	pkt_arp->sender_ip_addr = ip->src;
	pkt_arp->target_hw_addr.FromString("00:00:00:00:00:00");
	pkt_arp->target_ip_addr = ip->dst;

	return pkt;
}

ADD_MODULE(ArpQuerier, "arp_querier", "Queries ARP request if doesn't have MAC entry.")
