#include "dysco_nonsyn.h"

DyscoNonSyn::DyscoNonSyn() : Module() {
}

void process_payload(bess::Packet* pkt, uint8_t* payload) {
  
}

uint8_t* get_payload(bess::Packet* pkt) {
  Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
  size_t tcp_hlen = tcp->offset << 2;
  
  return reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
}

void DyscoNonSyn::ProcessBatch(bess::PacketBatch* batch) {
  int cnt = batch->cnt();

  bess::Packet* pkt;
  for(int i = 0; i < cnt; i++) {
    pkt = batch->pkts()[i];
    process_payload(pkt, get_payload(pkt));
  }
  
  //RunChooseModule(0, batch);
}

ADD_MODULE(DyscoNonSyn, "dysco_nonsyn", "processes TCP NON-SYN fragment")
