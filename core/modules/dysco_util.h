#ifndef BESS_MODULES_DYSCOUTIL_H_
#define BESS_MODULES_DYSCOUTIL_H_

//#include <netinet/tcp.h>

#include <string>
#include <thread>
#include <stdio.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
//#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unordered_map>
#include <rte_hash_crc.h>


#include "../port.h"
#include "../module.h"
#include "../utils/ip.h"
#include "../utils/arp.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/ether.h"
#include "../module_graph.h"
#include "../utils/endian.h"
#include "../utils/format.h"
#include "../utils/checksum.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/dysco_vport.h"

#include "dysco_policies.h"
#include "dysco_port_inc.h"
#include "dysco_port_out.h"

using std::mutex;
using std::string;
using std::size_t;
using std::thread;
using std::unordered_map;

using bess::Packet;
using bess::utils::Arp;
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::PacketBatch;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::CalculateIpv4Checksum;
using bess::utils::CalculateIpv4TcpChecksum;
using bess::utils::UpdateChecksumWithIncrement;

/*********************************************************************
 *
 *	Defines and Enums
 *
 *********************************************************************/
enum {
	DYSCO_ONE_PATH = 0,
	DYSCO_ADDING_NEW_PATH,
	DYSCO_ACCEPTING_NEW_PATH,
	DYSCO_INITIALIZING_NEW_PATH,
	DYSCO_MANAGING_TWO_PATHS,
	DYSCO_FINISHING_OLD_PATH,
	DYSCO_UNLOCKED,
	DYSCO_LOCK_PENDING,
	DYSCO_LOCKED,
	DYSCO_CLOSED_OLD_PATH
};

enum {
	DYSCO_CLOSED = 0,
	DYSCO_SYN_SENT,
	DYSCO_SYN_RECEIVED,
	DYSCO_ESTABLISHED,
	DYSCO_FIN_WAIT_1,
	DYSCO_FIN_WAIT_2,
	DYSCO_CLOSING,
	DYSCO_CLOSE_WAIT,
	DYSCO_LAST_ACK
};

enum {
	// Locking protocol
	DYSCO_CLOSED_LOCK = 0,
	DYSCO_REQUEST_LOCK,
	DYSCO_ACK_LOCK,
	DYSCO_NACK_LOCK,
	
	// Reconfiguration
	DYSCO_SYN,
	DYSCO_SYN_ACK,
	DYSCO_ACK,
	DYSCO_FIN,
	DYSCO_FIN_ACK,
	
	// Management
	DYSCO_POLICY,
	DYSCO_REM_POLICY,
	DYSCO_CLEAR,
	DYSCO_CLEAR_ALL,
	DYSCO_BUFFER_PACKET,
	DYSCO_TCP_SPLICE,
	DYSCO_COPY_STATE,
	DYSCO_PUT_STATE,
	DYSCO_STATE_TRANSFERRED,
	DYSCO_ACK_ACK,
	DYSCO_GET_MAPPING,
	DYSCO_GET_REC_TIME,

	// Locking
	DYSCO_LOCK,
	DYSCO_RECONFIG
};

#define NOSTATE_TRANSFER	        0
#define STATE_TRANSFER		        1
#define DYSCO_TCP_OPTION                253
#define DYSCO_TCP_OPTION_LEN            8
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_PERBLOCK           8

#define LOCKING_OPTION                  254
#define LOCKING_OPTION_LEN              4

/*
#define DYSCO_SYN_SENT			DYSCO_ADDING_NEW_PATH
#define DYSCO_SYN_RECEIVED		DYSCO_ACCEPTING_NEW_PATH
#define DYSCO_ESTABLISHED		DYSCO_INITIALIZING_NEW_PATH
#define DYSCO_LAST_ACK                  DYSCO_FINISHING_OLD_PATH
#define DYSCO_CLOSED                    DYSCO_CLOSED_OLD_PATH
*/
#define DEBUG                           1 
#define TTL                             32
#define PORT_RANGE                      65536
#define CNTLIMIT                        1
#define SLEEPTIME                       100000 /* usec */  // 100 ms
#define DEFAULT_TIMEOUT                 500000 /* usec */  // 500 ms

/*********************************************************************
 *
 *	TCP classes
 *
 *********************************************************************/

class DyscoTcpSession {
 public:
	uint32_t sip;
	uint32_t dip;
	uint16_t sport;
	uint16_t dport;

	bool operator==(const DyscoTcpSession& t) const {
		return sip == t.sip && sport == t.sport && dip == t.dip && dport == t.dport;
	}
};

class DyscoTcpSessionHash {
 public:
	size_t operator()(const DyscoTcpSession& t) const {
		return rte_hash_crc(&t, sizeof(uint64_t), 0);
	}
};

class DyscoTcpSessionEqualTo {
 public:
	bool operator()(const DyscoTcpSession& a, const DyscoTcpSession& b) const {
		return a.sip == b.sip && a.dip == b.dip && a.sport == b.sport && a.dport == b.dport;
	}
};

class DyscoTcpOption {
 public:
	uint8_t kind;
	uint8_t len;
	uint16_t padding;
	uint32_t tag;
};

class DyscoTcpTs {
 public:
	uint32_t ts;
	uint32_t tsr;
};

/* TCP classes */

/*********************************************************************
 *
 *	Retransmission classes
 *
 *********************************************************************/
template <typename T>
class LNode {
public:
	T element;
	LNode* next;
	LNode* prev;
	uint64_t ts;
	uint32_t cnt;
	bool isRemoved;
	
 LNode(const T& e = T(), LNode* n = 0, LNode* p = 0)
	 : element(e), next(n), prev(p) {
		ts = 0;
		cnt = 0;
		isRemoved = false;
	}
	
	~LNode() {
		if(prev)
			prev->next = next;

		if(next)
			next->prev = prev;
	}

	void setTs(uint64_t t) {
		ts = t;
	}
};

template <typename T>
class LinkedList {
private:
	LNode<T>* head;
	LNode<T>* tail;

public:
	LinkedList() {
		head = new LNode<T>();
		tail = new LNode<T>();

		head->next = tail;
		tail->prev = head;
	}

	~LinkedList() {
		clear();
		
		delete head;
		delete tail;
	}

	LNode<T>* getHead() {
		return head;
	}

	LNode<T>* getTail() {
		return tail;
	}
	
	void clear() {
		while(tail->prev != head) {
			LNode<T>* toRemove = tail->prev;
			tail->prev = toRemove->prev;
			
			delete toRemove;
		}
	}

	bool remove(LNode<T>* node) {
		if(!node)
			return false;

		delete node;

		return true;
	}

	LNode<T>* insertHead(T& element, uint64_t ts = 0) {
		LNode<T>* node = new LNode<T>(element);

		head->next->prev = node;
		node->next = head->next;
		node->prev = head;
		head->next = node;

		node->setTs(ts);
		
		return node;
	}

	LNode<T>* insertTail(T& element, uint64_t ts = 0) {
		LNode<T>* node = new LNode<T>(element);

		tail->prev->next = node;
		node->prev = tail->prev;
		node->next = tail;
		tail->prev = node;

		node->setTs(ts);
		
		return node;
	}
};

/* Retransmission classes */

/*********************************************************************
 *
 *	Dysco classes
 *
 *********************************************************************/
class DyscoControlMessage {
 public:
	DyscoTcpSession my_sub;
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	uint32_t leftA;
	uint32_t rightA;

	uint16_t sport;
	uint16_t dport;

	uint32_t leftIseq;
	uint32_t leftIack;

	uint32_t rightIseq;
	uint32_t rightIack;

	uint32_t seqCutoff;

	uint32_t leftIts;
	uint32_t leftItsr;

	uint16_t leftIws;
	uint16_t leftIwsr;

	uint16_t sackOk;
	uint16_t semantic;

	uint32_t srcMB;
	uint32_t dstMB;

	uint8_t lhop;
	uint8_t rhop;
	uint8_t lock_state;
	uint8_t type;
};

class DyscoHashOut;

class DyscoHashIn {
 public:
	DyscoTcpSession sub;
	DyscoTcpSession my_sup;
	DyscoTcpSession neigh_sup;

	Ethernet mac_sub;
	
	DyscoHashOut* dcb_out;

	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	
	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	uint8_t two_paths:1,
		ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		tsr_add:1,
		ws_ok:1;
	
	uint8_t is_reconfiguration:1,
		padding:7;
	
	DyscoControlMessage cmsg;
	Module* module;
};

class DyscoHashOut {
 public:
	DyscoHashIn* dcb_in;
	DyscoTcpSession sub;
	DyscoTcpSession sup;

	Ethernet mac_sub;
	
	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	uint32_t seq_cutoff;
	uint32_t ack_cutoff;

	uint32_t last_seq;
	uint32_t last_ack;
	
	uint32_t* sc;
	uint32_t sc_len;
	DyscoHashOut* other_path;

	uint32_t ts_in;
	uint32_t ts_out;
	uint32_t ts_delta;
	uint32_t tsr_in;
	uint32_t tsr_out;
	uint32_t tsr_delta;
	uint32_t dysco_tag;

	uint16_t ws_in;
	uint16_t ws_out;
	uint16_t ws_delta;

	uint8_t old_path:1,
		valid_ack_cut:1,
		use_np_seq:1,
		use_np_ack:1,
		state_t:1,
		free_sc:1;
	uint8_t ack_add:1,
		seq_add:1,
		sack_ok:1,
		ts_ok:1,
		ts_add:1,
		ws_ok:1,
		tsr_add:1,
		tag_ok:1;


	uint8_t is_reconfiguration:1,
		is_nat:1,
		is_LA:1,
		is_RA:1,
		state:4;

	uint8_t lock_state:7,
		is_signaler:1;
	
	uint32_t ack_ctr;

	DyscoControlMessage cmsg;
	Module* module;
};

class DyscoCbReconfig {
 public:
	DyscoTcpSession super;
	DyscoTcpSession leftSS;
	DyscoTcpSession rightSS;
	DyscoTcpSession sub_out;
	DyscoTcpSession sub_in;

	DyscoHashOut* old_dcb;
	DyscoHashOut* new_dcb;

	uint32_t leftIseq;
	uint32_t leftIack;
	uint32_t leftIts;
	uint32_t leftItsr;
	uint16_t leftIws;
	uint16_t leftIwsr;

	uint8_t sack_ok;
};

/* Dysco classes */

class DyscoHashes {
 public:
	string ns;
	uint32_t index;
	uint32_t dysco_tag;
	DyscoPolicies policies;

	unordered_map<uint32_t, DyscoHashOut*> hash_pen_tag;
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_pen;
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash> hash_reconfig;

	//by devip
	unordered_map<uint32_t, mutex*> mutexes;
	unordered_map<uint32_t, LinkedList<Packet>* > retransmission_list;
	unordered_map<uint32_t, unordered_map<uint32_t, LNode<Packet>* >* > received_hash;
};


/*********************************************************************
 *
 *	DEBUG
 *
 *********************************************************************/
inline char* printIP(uint32_t ip) {
	uint8_t bytes[4];
        char* buf = (char*) malloc(17);
	
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        sprintf(buf, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);

        return buf;
}

inline char* printSS(DyscoTcpSession ss) {
	char* buf = (char*) malloc(64);
	sprintf(buf, "%s:%u -> %s:%u",
		printIP(ntohl(ss.sip)), ntohs(ss.sport),
		printIP(ntohl(ss.dip)), ntohs(ss.dport));

	return buf;
}

inline char* printPacketSS(Ipv4* ip, Tcp* tcp) {
	char* buf = (char*) malloc(64);
	sprintf(buf, "%s:%u -> %s:%u",
		printIP(ip->src.value()), tcp->src_port.value(),
		printIP(ip->dst.value()), tcp->dst_port.value());

	return buf;
}

/*********************************************************************
 *
 *	Auxiliary methods
 *
 *********************************************************************/
inline bool isIP(Ethernet* eth) {
	return eth->ether_type.value() == Ethernet::Type::kIpv4;
}

inline bool isARPReply(Ethernet* eth) {
	if(eth->ether_type.value() != Ethernet::Type::kArp)
		return false;

	Arp* arp = reinterpret_cast<Arp*>(eth + 1);
	return arp->opcode.value() == Arp::kReply;
}

inline bool isTCP(Ipv4* ip) {
	return ip->protocol == Ipv4::Proto::kTcp;
}

inline bool isTCPSYN(Tcp* tcp, bool exclusive = false) {
	return exclusive ? tcp->flags == Tcp::Flag::kSyn : tcp->flags & Tcp::Flag::kSyn;
}
	
inline bool isTCPACK(Tcp* tcp, bool exclusive = false) {
	return exclusive ? tcp->flags == Tcp::Flag::kAck : tcp->flags & Tcp::Flag::kAck;
}

inline bool isTCPFIN(Tcp* tcp, bool exclusive = false) {
	return exclusive ? tcp->flags == Tcp::Flag::kFin : tcp->flags & Tcp::Flag::kFin;
}

inline bool before(uint32_t seq1, uint32_t seq2) {
	return (int32_t)(seq1 - seq2) < 0;
}

inline bool after(uint32_t seq2, uint32_t seq1) {
	return before(seq1, seq2);
}

inline bool isFromLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.raw_value() == cmsg->leftA;
}

inline bool isFromRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.raw_value() == cmsg->rightA;
}

inline bool isToLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.raw_value() == cmsg->leftA;
}

inline bool isToRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.raw_value() == cmsg->rightA;
}

inline uint32_t hasPayload(Ipv4* ip, Tcp* tcp) {
	return ip->length.value() - (ip->header_length << 2) - (tcp->offset << 2);
}

inline uint32_t getValueToAck(Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	Tcp* tcp = reinterpret_cast<Tcp*>((uint8_t*) ip + (ip->header_length << 2));

	uint32_t toAck = tcp->seq_num.value() + hasPayload(ip, tcp);
	if(isTCPSYN(tcp))
	   toAck++;

	return toAck;
}

inline void update_four_tuple(Ipv4* ip, Tcp* tcp, DyscoTcpSession& ss) {
	ss.sip = ip->src.raw_value();
	ss.dip = ip->dst.raw_value();
	ss.sport = tcp->src_port.raw_value();
	ss.dport = tcp->dst_port.raw_value();
}

inline void hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	*((uint32_t*)(&ip->src)) = ss->sip;
	*((uint32_t*)(&ip->dst)) = ss->dip;
	*((uint16_t*)(&tcp->src_port)) = ss->sport;
	*((uint16_t*)(&tcp->dst_port)) = ss->dport;
}

inline void hdr_rewrite_csum(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	uint32_t incremental = 0;

	incremental += ChecksumIncrement32(ip->src.raw_value(), ss->sip);
	incremental += ChecksumIncrement32(ip->dst.raw_value(), ss->dip);
	
	ip->checksum  = UpdateChecksumWithIncrement( ip->checksum, incremental);
	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);

	incremental  = ChecksumIncrement16(tcp->src_port.raw_value(), ss->sport);
	incremental += ChecksumIncrement16(tcp->dst_port.raw_value(), ss->dport);

	tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, incremental);

	hdr_rewrite(ip, tcp, ss);
}

inline void fix_csum(Ipv4* ip, Tcp* tcp) {
	ip->checksum = 0;
	tcp->checksum = 0;
	ip->checksum = CalculateIpv4Checksum(*ip);
	tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);	
}

inline void hdr_rewrite_full_csum(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	hdr_rewrite(ip, tcp, ss);
	fix_csum(ip, tcp);
}

inline void* getPayload(Tcp* tcp) {
	return reinterpret_cast<void*>(reinterpret_cast<char*>(tcp) + (tcp->offset << 2));
}

inline bool isLockingSignalPacket(Tcp* tcp) {
	if(tcp->offset < 6)
		return false;

	DyscoTcpOption* tcpo = reinterpret_cast<DyscoTcpOption*>(tcp + 1);
	
	return tcpo->kind == LOCKING_OPTION;
}

inline bool isLockingPacket(Ipv4* ip, Tcp* tcp) {
	uint32_t payload_len = hasPayload(ip, tcp);

	if(isTCPSYN(tcp) && payload_len) {
		if(payload_len >= sizeof(DyscoControlMessage)) {
			DyscoControlMessage* cmsg = reinterpret_cast<DyscoControlMessage*>(tcp + 1);
			return cmsg->type == DYSCO_LOCK;
		}
	}

	return false;
}

inline bool isLeftAnchor(DyscoTcpOption* tcpo) {
	return (tcpo->padding >> 4) == 0;
}

inline DyscoTcpTs* get_ts_option(Tcp* tcp) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_TIMESTAMP && opsize == TCPOLEN_TIMESTAMP)
				return reinterpret_cast<DyscoTcpTs*>(ptr);

			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return 0;
}

inline bool tcp_sack(Tcp* tcp, uint32_t delta, uint8_t add) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	uint32_t opcode;
	uint32_t opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return 0;

		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return 0;

			if(opsize > len)
				return 0;

			if(opcode == TCPOPT_SACK) {
				if((opsize >= (TCPOLEN_SACK_BASE + TCPOLEN_SACK_PERBLOCK))
				   &&
				   !((opsize - TCPOLEN_SACK_BASE) % TCPOLEN_SACK_PERBLOCK)) {
					uint8_t* lptr = ptr;
					uint32_t blen = opsize - 2;

					while(blen > 0) {
						uint32_t* left_edge = (uint32_t*) lptr;
						uint32_t* right_edge = (uint32_t*) (lptr + 4);
						uint32_t new_ack_l, new_ack_r;
						if(add) {
							new_ack_l = htonl(ntohl(*left_edge) + delta);
							new_ack_r = htonl(ntohl(*right_edge) + delta);						
						} else {
							new_ack_l = htonl(ntohl(*left_edge) - delta);
							new_ack_r = htonl(ntohl(*right_edge) - delta);						
						}

						*left_edge = new_ack_l;
						*right_edge = new_ack_r;

						lptr += 8;
						blen -= 8;
					}
				}
			}
			ptr += opsize - 2;
			len -= opsize;
		}
	}

	return true;
}

inline bool parse_tcp_syn_opt_s(Tcp* tcp, DyscoHashOut* cb_out) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_out->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			switch(opsize) {
			case TCPOPT_WINDOW:
				if(opsize == TCPOLEN_WINDOW) {
					uint8_t snd_wscale = *(uint8_t*)ptr;
					
					cb_out->ws_ok = 1;
					cb_out->ws_delta = 0;
					if (snd_wscale > 14)
						snd_wscale = 14;
					
					cb_out->ws_in = cb_out->ws_out = snd_wscale;
				}
				
				break;
				
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP) {
					if(tcp->flags & Tcp::kAck) {
						uint32_t ts, tsr;
						
						cb_out->ts_ok = 1;
						ts = (uint32_t)(*ptr);
						tsr = (uint32_t)(*(ptr + 4));
						cb_out->ts_in = cb_out->ts_out = ts;
						cb_out->tsr_in = cb_out->tsr_out = tsr;
						
						cb_out->ts_delta = cb_out->tsr_delta = 0;
					}
				}
				
				break;
				
			case TCPOPT_SACK_PERMITTED:
				if(opsize == TCPOLEN_SACK_PERMITTED)
					cb_out->sack_ok = 1;
				
				break;

			case DYSCO_TCP_OPTION:
				cb_out->tag_ok = 1;
				cb_out->dysco_tag = *(uint32_t*)ptr;
				
				break;
			}

			ptr += opsize - 2;
			len -= opsize;
		}
	}
	
	return true;
}

inline bool parse_tcp_syn_opt_r(Tcp* tcp, DyscoHashIn* cb_in) {
	uint32_t len = (tcp->offset << 2) - sizeof(Tcp);
	uint8_t* ptr = reinterpret_cast<uint8_t*>(tcp + 1);

	cb_in->sack_ok = 0;

	uint32_t opcode, opsize;
	while(len > 0) {
		opcode = *ptr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return false;
			
		case TCPOPT_NOP:
			len--;
			continue;

		default:
			opsize = *ptr++;
			if(opsize < 2)
				return false;
			
			if(opsize > len)
				return false;
			
			switch(opsize) {
			case TCPOPT_WINDOW:
				if(opsize == TCPOLEN_WINDOW) {
					uint8_t snd_wscale = *(uint8_t*)ptr;
					
					cb_in->ws_ok = 1;
					cb_in->ws_delta = 0;
					if (snd_wscale > 14)
						snd_wscale = 14;
					
					cb_in->ws_in = cb_in->ws_out = snd_wscale;
				}
				
				break;
				
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP) {
					if(tcp->flags & Tcp::kAck) {
						uint32_t ts, tsr;
						
						cb_in->ts_ok = 1;
						ts = (uint32_t)(*ptr);
						tsr = (uint32_t)(*(ptr + 4));
						cb_in->ts_in = cb_in->ts_out = ts;
						cb_in->tsr_in = cb_in->tsr_out = tsr;
						
						cb_in->ts_delta = cb_in->tsr_delta = 0;
					}
				}
				
				break;
				
			case TCPOPT_SACK_PERMITTED:
				if(opsize == TCPOLEN_SACK_PERMITTED)
					cb_in->sack_ok = 1;
				
				break;

			ptr += opsize - 2;
			len -= opsize;
			}
		}
	}
	
	return true;
}

inline DyscoHashIn* insert_cb_out_reverse(DyscoHashOut* cb_out, uint8_t two_paths, DyscoControlMessage* cmsg = 0) {
	DyscoHashIn* cb_in = new DyscoHashIn();

	cb_in->sub.sip = cb_out->sub.dip;
	cb_in->sub.dip = cb_out->sub.sip;
	cb_in->sub.sport = cb_out->sub.dport;
	cb_in->sub.dport = cb_out->sub.sport;

	cb_in->my_sup.sip = cb_out->sup.dip;
	cb_in->my_sup.dip = cb_out->sup.sip;
	cb_in->my_sup.sport = cb_out->sup.dport;
	cb_in->my_sup.dport = cb_out->sup.sport;

	cb_in->in_iack = cb_in->out_iack = cb_out->out_iseq;
	cb_in->in_iseq = cb_in->out_iseq = cb_out->out_iack;

	cb_in->seq_delta = cb_in->ack_delta = 0;
	cb_in->ts_ok = cb_out->ts_ok;
	cb_in->ts_in = cb_in->ts_out = cb_out->tsr_in;
	cb_in->ts_delta = 0;
	cb_in->tsr_in = cb_in->tsr_out = cb_out->ts_in;
	cb_in->tsr_delta = 0;
	cb_in->ws_ok = cb_out->ws_ok;
	cb_in->ws_in = cb_in->ws_out = cb_out->ws_in;
	cb_in->ws_delta = 0;
	cb_in->sack_ok = cb_out->sack_ok;
	cb_in->two_paths = two_paths;

	if(cmsg)
		memcpy(&cb_in->cmsg, cmsg, sizeof(DyscoControlMessage));

	if(two_paths == 1) {
		cb_in->is_reconfiguration = 1;
	}
	
	cb_in->dcb_out = cb_out;
	
	return cb_in;
}

#endif //BESS_MODULES_DYSCOUTIL_H_
