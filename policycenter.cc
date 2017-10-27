#include "policycenter.h"

#include "../utils/checksum.h"
#include "../utils/common.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/icmp.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using IpProto = bess::utils::Ipv4::Proto;
using bess::utils::Udp;
using bess::utils::Tcp;
using bess::utils::Icmp;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;

void PolicyCenter::create_mapping(bess::Packet* pkt, struct tcp_session* ss) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  struct tcp_session s;
  struct tcp_session t;
  s.sip = ip->src;
  s.dip = ip->dst;
  s.sport = tcp->src_port;
  s.dport = tcp->dst_port;

  map.Insert(s, *ss);
  map.Insert(*ss, s);

  s.dip = ip->src;
  s.sip = ip->dst;
  s.dport = tcp->src_port;
  s.sport = tcp->dst_port;
  t.sip = ss->dip;
  t.dip = ss->sip;
  t.sport = ss->dport;
  t.dport = ss->sport;
  
  map.Insert(s, t);
  map.Insert(t, s);
}

uint8_t* PolicyCenter::get_payload(bess::Packet* pkt) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);
  size_t tcp_hlen = tcp->offset << 2;
  
  return reinterpret_cast<uint8_t*>(tcp) + tcp_hlen;
}

struct tcp_session* PolicyCenter::find_mapping(bess::Packet* pkt) {
  struct tcp_session ss;
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  ss.sip = ip->src;
  ss.dip = ip->dst;
  ss.sport = tcp->src_port;
  ss.dport = tcp->dst_port;

  auto* newss = map.Find(ss);
  if(newss != nullptr)
     return &newss->second;

  return 0;
}

void PolicyCenter::restore_super_session(bess::Packet* pkt, struct tcp_session* ss) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  ip->src = ss->sip;
  ip->dst = ss->dip;
  tcp->src_port = ss->sport;
  tcp->dst_port = ss->dport;
}

void PolicyCenter::remove_payload(bess::Packet* pkt) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  uint32_t payload_length = ip->length.value() - (tcp->offset * 4 + ip_hlen);
  
  if(payload_length)
    pkt->trim(payload_length);

  ip->length = ip->length - be16_t(payload_length);
}

void PolicyCenter::ProcessBatch(bess::PacketBatch* batch) {
  int cnt = batch->cnt();
  gate_idx_t ingate = get_igate();

  bess::Packet* pkt;
  
  if(ingate == 0) {
    //SYN
  } else if(ingate == 1) {
    //SYN+P
    uint8_t* payload;
    for(int i = 0; i < cnt; i++) {
      pkt = batch->pkts()[i];
      
      payload = get_payload(pkt);
      create_mapping(pkt, (struct tcp_session*) payload);
      restore_super_session(pkt, (struct tcp_session*) payload);
      remove_payload(pkt);
    }

    RunChooseModule(0, batch);
  } else {
    //NON-SYN
    struct tcp_session* ss;
    for(int i = 0; i < cnt; i++) {
      pkt = batch->pkts()[i];

      ss = find_mapping(pkt);
      if(ss)
        restore_super_session(pkt, ss);
    }

    RunChooseModule(0, batch);
  }

  //RunChooseModule(0, batch);
}

ADD_MODULE(PolicyCenter, "PolicyCenter", "...")
