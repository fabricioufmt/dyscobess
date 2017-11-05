#include "dysco_policycenter.h"

#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;

DyscoPolicyCenter::DyscoPolicyCenter() : Module() {

}

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

void DyscoPolicyCenter::ProcessBatch(bess::PacketBatch* batch) {
  bess::PacketBatch out_batches[3];
  bess::Packet **ptrs[3];

  ptrs[0] = out_batches[0].pkts();
  ptrs[1] = out_batches[1].pkts();
  ptrs[2] = out_batches[2].pkts();

  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    if(isTCPSYN(pkt)) {
      if(hasPayload(pkt))
	*(ptrs[1]++) = pkt;
      else
	*(ptrs[0]++) = pkt;
    } else
      *(ptrs[2]++) = pkt;
  }

  out_batches[0].set_cnt(ptrs[0] - out_batches[0].pkts());
  out_batches[1].set_cnt(ptrs[1] - out_batches[1].pkts());
  out_batches[2].set_cnt(ptrs[2] - out_batches[2].pkts());

  RunChooseModule(0, &out_batches[0]);
  RunChooseModule(1, &out_batches[1]);
  RunChooseModule(2, &out_batches[2]);
}

ADD_MODULE(DyscoPolicyCenter, "dysco_policycenter", "classifies packet as SYN, SYN+P and NON-SYN")
