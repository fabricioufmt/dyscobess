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

void swapIP(struct tcp_session* ss) {
  be32_t swap = ss->sip;
  ss->sip = ss->dip;
  ss->dip = swap;
}

void swapPort(struct tcp_session* ss) {
  be16_t swap = ss->sport;
  ss->sport = ss->dport;
  ss->dport = swap;
}

/*
  Receive: subss -> supss (payload)
  4 Mapping: 
     1. subss -> supss
     2. inv(subss) -> inv(supss)
     3. supss -> session(dst(subss)->firstip on sc)
     4. inv(supss) -> inv(session(dst(subss)->first on sc)
*/
void PolicyCenter::create_mapping(bess::Packet* pkt, uint8_t* payload) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  uint32_t sclen = (ip->length.value() - tcp->offset * 4 - ip_hlen - sizeof(struct tcp_session))/sizeof(uint32_t);

  be32_t* sc = 0;
  struct dysco_cb t;
  struct tcp_session subss;
  struct tcp_session supss;
  subss.sip = ip->src;
  subss.dip = ip->dst;
  subss.sport = tcp->src_port;
  subss.dport = tcp->dst_port;
  //supss = *((struct tcp_session*) payload);
  memcpy(&supss, payload, sizeof(struct tcp_session));

  // Mapping 1
  t.subss = subss;
  t.supss = supss;
  //copying from 2nd ip on service chain?
  //because if I received, I'm first ip in service chain
  if(sclen != 0) {
    sc = (be32_t*) malloc((sclen - 1) * sizeof(be32_t));
    t.sc = sc;
    t.sclen = be32_t(sclen);
    memcpy(t.sc, payload + sizeof(tcp_session) + sizeof(uint32_t), (sclen - 1) * sizeof(be32_t));
  } else {
    t.sc = 0;
    t.sclen = be32_t(0);
  }
  map.Insert(subss, t);

  //Mapping 3
  subss.sip = be32_t(*(int*)(payload + sizeof(struct tcp_session)));
  subss.dip = be32_t(*(int*)(payload + sizeof(struct tcp_session) + sizeof(uint32_t)));
  subss.sport = be16_t(8000);
  subss.dport = be16_t(8000);
  //subss.sport = be16_t((rand() % 1000) + 10000);
  //subss.dport = be16_t((rand() % 1000) + 30000);
  t.supss = subss;
  t.subss = supss;
  t.sc = sc;
  t.sclen = be32_t(sclen - 1);
  map.Insert(supss, t);

  //Mapping 4
  supss = *((struct tcp_session*) payload);
  swapIP(&subss);
  swapPort(&subss);
  swapIP(&supss);
  swapPort(&supss);
  t.subss = supss;
  t.supss = subss;
  t.sc = 0;
  t.sclen = be32_t(0);
  map.Insert(supss, t);
  
  //Mapping 2
  subss.dip = ip->src;
  subss.sip = ip->dst;
  subss.dport = tcp->src_port;
  subss.sport = tcp->dst_port;
  t.supss = supss;
  t.subss = subss;
  t.sc = 0;
  t.sclen = be32_t(0);
  map.Insert(subss, t);
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
     return &newss->second.supss;

  return 0;
}

void PolicyCenter::restore_super_session(bess::Packet* pkt) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  struct tcp_session* supss = find_mapping(pkt);
  
  if(supss) {
    ip->src = supss->sip;
    ip->dst = supss->dip;
    tcp->src_port = supss->sport;
    tcp->dst_port = supss->dport;
  }
}

void PolicyCenter::restore_syn_p(bess::Packet* pkt) {
  Ethernet* eth = pkt->head_data<Ethernet*>();
  Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
  size_t ip_hlen = ip->header_length << 2;
  Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + ip_hlen);

  struct tcp_session ss;
  ss.sip = ip->src;
  ss.dip = ip->dst;
  ss.sport = tcp->src_port;
  ss.dport = tcp->dst_port;

  auto* value = map.Find(ss);
  if(value == nullptr)
    return;
  struct dysco_cb cb = value->second;

  ip->src = cb.supss.sip;
  ip->dst = cb.supss.dip;
  tcp->src_port = cb.supss.sport;
  tcp->dst_port = cb.supss.dport;
  
  uint8_t* payload = (uint8_t*) pkt->append(sizeof(struct tcp_session));
  memcpy(payload, &cb.subss, sizeof(struct tcp_session));
  ip->length = ip->length + be16_t(sizeof(struct tcp_session));
  /*uint8_t* payload = (uint8_t*) pkt->append(sizeof(struct tcp_session) + cb.sclen.value() * sizeof(uint32_t));
  memcpy(payload, &cb.subss, sizeof(struct tcp_session));
  memcpy(payload + sizeof(struct tcp_session), cb.sc, cb.sclen.value() * sizeof(uint32_t));

  ip->length = ip->length + be16_t(sizeof(struct tcp_session) + cb.sclen.value() * sizeof(uint32_t));*/
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
    /*for(int i = 0; i < cnt; i++) {
       pkt = batch->pkts()[i];

       restore_syn_p(pkt);
    } */
  } else if(ingate == 1) {
    //SYN+P
    uint8_t* payload;
    for(int i = 0; i < cnt; i++) {
      pkt = batch->pkts()[i];
      
      payload = get_payload(pkt);
      create_mapping(pkt, payload);
      restore_super_session(pkt);
      remove_payload(pkt);
    }

    //RunChooseModule(0, batch);
  } else {
    //NON-SYN
    for(int i = 0; i < cnt; i++) {
      pkt = batch->pkts()[i];
      
      restore_super_session(pkt);
    }

    //RunChooseModule(0, batch);
  }

  RunChooseModule(0, batch);
}

ADD_MODULE(PolicyCenter, "PolicyCenter", "...")
