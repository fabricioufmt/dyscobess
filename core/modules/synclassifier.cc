#include <arpa/inet.h>
#include "synclassifier.h"

#include "utils/ip.h"
#include "utils/tcp.h"
#include "utils/ether.h"

void SynClassifier::ProcessBatch(bess::PacketBatch* batch) {
  using bess::utils::Tcp;
  using bess::utils::Ipv4;
  using bess::utils::Ethernet;
  using bess::utils::be16_t;

  int cnt = batch->cnt();

  gate_idx_t out_gates[bess::PacketBatch::kMaxBurst];
  
  for(int i = 0; i < cnt; i++) {
    bess::Packet* pkt = batch->pkts()[i];

    Ethernet* eth = pkt->head_data<Ethernet*>();
    Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
    size_t ip_hlen = ip->header_length * 4;
    Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

    be16_t headers_len = be16_t(tcp->offset * 4 + ip->header_length * 4);
    
    if(tcp->flags == 0x02) {
      if(ip->length != headers_len) {
	out_gates[i] = 1;
      } else {
	out_gates[i] = 0;
      }
    } else {
	out_gates[i] = 2;
    }
  }
  RunSplit(out_gates, batch);
}

ADD_MODULE(SynClassifier, "SynClassifier", "classifies packets SYN without payload, SYN with payload, or non-SYN")
