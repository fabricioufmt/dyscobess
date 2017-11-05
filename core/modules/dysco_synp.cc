#include "dysco_synp.h"

DyscoSynP::DyscoSynP() : Module() {
  
}

void process_packet(bess::Packet* pkt) {
  Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
  ip = nullptr;
  /*
  Ipv4* ip = reinterpret_cast<Ipv4*>(pkt->head_data<Ethernet*>() + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
  size_t tcp_hlen = tcp->offset << 2;
  uint16_t ip_len = ip->length.value();
  uint8_t* payload = reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
  int sc_len = (ip_len - ip_hlen - tcp_hlen - sizeof(struct tcp_session))/sizeof(uint32_t);
  uint32_t* sc = (uint32_t*) (payload + sizeof(struct tcp_session));
  
  struct tcp_session subss;
  struct tcp_session nextss;
  struct tcp_session* supss = (struct tcp_session*) payload;
  subss.sip = ip->src.value();
  subss.dip = ip->dst.value();
  subss.sport = tcp->src_port.value();
  subss.dport = tcp->dst_port.value();
  if(sc_len != 1) {
    next.sip = subss.dip;
    next.dip = sc[1]; //sc[0] is yourself
    next.sport = (rand() % 1000) + 10000;
    next.sport = (rand() % 1000) + 30000;
  } else {
    next.sip = next.dip = 0;
    next.sport = next.dport = 0;
  }
  */
  //Send (subss, supss, nextss, sc_len, sc) to DyscoPolicyCenter
}

void DyscoSynP::ProcessBatch(bess::PacketBatch* batch) {
  int cnt = batch->cnt();

  bess::Packet* pkt;
  for(int i = 0; i < cnt; i++) {
    pkt = batch->pkts()[i];
    process_packet(pkt);
  }

  RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynP, "dysco_synp", "processes TCP SYN with Payload fragment")
