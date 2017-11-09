#include "dysco_bpf.h"
#include "dysco_classifier.h"

bool isTCPSYN(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

	return tcp->flags == Tcp::Flag::kSyn;
}

bool hasPayload(bess::Packet* pkt) {
	Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
	size_t ip_hlen = ip->header_length << 2;
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
	size_t tcp_hlen = tcp->offset << 2;

	return (ip->length.value() - ip_hlen - tcp_hlen) != 0;
}
/*
  0 = SYN
  1 = SYN + PAYLOAD
  2 = NON-SYN
  3 = NON IP OR NON TCP
 */
void DyscoClassifier::ProcessBatch(bess::PacketBatch* batch) {
	bess::PacketBatch out_batches[4];
	bess::Packet **ptrs[4];

	ptrs[0] = out_batches[0].pkts();
	ptrs[1] = out_batches[1].pkts();
	ptrs[2] = out_batches[2].pkts();
	ptrs[3] = out_batches[3].pkts();

	int cnt = batch->cnt();

	for (int i = 0; i < cnt; i++) {
		bess::Packet *pkt = batch->pkts()[i];

		if (bpf->Match(bpf->filters_[0], pkt->head_data<u_char *>(), pkt->total_len(), pkt->head_len())) {
			if(isTCPSYN(pkt)) {
				if(hasPayload(pkt))
					*(ptrs[1]++) = pkt;
				else
					*(ptrs[0]++) = pkt;
			} else
				*(ptrs[2]++) = pkt;
		} else {
			*(ptrs[3]++) = pkt;
		}
	}

	out_batches[0].set_cnt(ptrs[0] - out_batches[0].pkts());
	out_batches[1].set_cnt(ptrs[1] - out_batches[1].pkts());
	out_batches[2].set_cnt(ptrs[2] - out_batches[2].pkts());
	out_batches[3].set_cnt(ptrs[3] - out_batches[3].pkts());
  
	RunChooseModule(0, &out_batches[0]);
	RunChooseModule(1, &out_batches[1]);
	RunChooseModule(2, &out_batches[2]);
	RunChooseModule(3, &out_batches[3]);
}

ADD_MODULE(DyscoClassifier, "dysco_classifier", "classifies packet as SYN, SYN+P, NON-SYN or TCP or non-TCP")
