#include "dysco_syn_inc.h"
#include "../module_graph.h"

CommandResponse DyscoSynInc::Init(const bess::pb::DyscoSynIncArg& arg) {
	const char* module_name;
	if(!arg.dyscocenter().length())
		return CommandFailure(EINVAL, "'dyscopolicy' must be given as string");

	module_name = arg.dyscocenter().c_str();

	const auto &it = ModuleGraph::GetAllModules().find(module_name);
	if(it == ModuleGraph::GetAllModules().end())
		return CommandFailure(ENODEV, "Module %s not found", module_name);

	dyscocenter = reinterpret_cast<DyscoCenter*>(it->second);
	
	return CommandSuccess();
}

char* printip(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

void DyscoSynInc::debug_info(bess::Packet* pkt, char* dir) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	fprintf(stderr, "DyscoSynInc(%s): %s:%u -> %s:%u\n", dir,
		printip(ip->src.value()), tcp->src_port.value(),
		printip(ip->dst.value()), tcp->dst_port.value());
}

bool DyscoSynInc::process_packet(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	if(!dyscocenter)
		return false;

	DyscoBPF::Filter* filter = dyscocenter->get_filter(pkt);
	DyscoControlBlock* cb = dyscocenter->get_controlblock_supss(ip, tcp);

	if(cb) {
		fprintf(stderr, "DyscoSynInc: cb is not NULL\n");
		DyscoTcpSession* ss = &cb->nextss;
		ip->src = be32_t(ntohl(ss->sip));
		ip->dst = be32_t(ntohl(ss->dip));
		tcp->src_port = be16_t(ntohs(ss->sport));
		tcp->dst_port = be16_t(ntohs(ss->dport));

		uint32_t payload_len = sizeof(DyscoTcpSession) + filter->sc_len;
		uint8_t* payload = (uint8_t*) pkt->append(payload_len);
		memcpy(payload, &cb->supss, sizeof(DyscoTcpSession));
		memcpy(payload + sizeof(DyscoTcpSession), filter->sc, filter->sc_len);

		ip->length = be16_t(ip->length.value() + payload_len);

		ip->checksum = 0;
		tcp->checksum = 0;
		ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
		tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
	} else {
		fprintf(stderr, "DyscoSynInc: cb is NULL\n");
		if(filter) {
			fprintf(stderr, "DyscoSynInc: filter is not NULL\n");
			DyscoTcpSession supss;
			supss.sip = htonl(ip->src.value());
			supss.dip = htonl(ip->dst.value());
			supss.sport = htons(tcp->src_port.value());
			supss.dport = htons(tcp->dst_port.value());

			//ip->dst = be32_t(htonl(*(uint32_t*)filter->sc));
			ip->dst = be32_t(ntohl(*(uint32_t*)filter->sc));
			//ip->dst = be32_t((*(uint32_t*)filter->sc));
			tcp->src_port = be16_t((rand() % 1000 + 10000));
			tcp->dst_port = be16_t((rand() % 1000 + 30000));

			uint32_t nsize = sizeof(DyscoTcpSession) + filter->sc_len;
			uint8_t* npayload = (uint8_t*) pkt->append(nsize);
			memcpy(npayload, &supss, sizeof(DyscoTcpSession));
			memcpy(npayload + sizeof(DyscoTcpSession), filter->sc, filter->sc_len);

			ip->length = be16_t(ip->length.value() + nsize);

			ip->checksum = 0;
			tcp->checksum = 0;
			ip->checksum = bess::utils::CalculateIpv4Checksum(*ip);
			tcp->checksum = bess::utils::CalculateIpv4TcpChecksum(*ip, *tcp);
		} else {
			fprintf(stderr, "DyscoSynInc: filter is NULL\n");
			return false;
		}
	}

	return true;
}

void DyscoSynInc::ProcessBatch(bess::PacketBatch* batch) {
	int cnt = batch->cnt();

	bess::Packet* pkt = 0;
	for(int i = 0; i < cnt; i++) {
		pkt = batch->pkts()[i];
		debug_info(pkt, (char*)"in/out");
	}
	RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynInc, "dysco_syn_inc", "processes TCP SYN segments incoming")
