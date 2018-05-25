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
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::PacketBatch;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;

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
	// Locking protocol
	DYSCO_REQUEST_LOCK = 1,
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
	DYSCO_GET_REC_TIME
};

#define NOSTATE_TRANSFER	        0
#define STATE_TRANSFER		        1
#define DYSCO_TCP_OPTION                253
#define DYSCO_TCP_OPTION_LEN            8
#define TCPOLEN_SACK_BASE               2
#define TCPOLEN_SACK_PERBLOCK           8
#define DYSCO_SYN_SENT			DYSCO_ADDING_NEW_PATH
#define DYSCO_SYN_RECEIVED		DYSCO_ACCEPTING_NEW_PATH
#define DYSCO_ESTABLISHED		DYSCO_INITIALIZING_NEW_PATH
#define DYSCO_LAST_ACK                  DYSCO_FINISHING_OLD_PATH
#define DYSCO_CLOSED                    DYSCO_CLOSED_OLD_PATH

//#define DEBUG                           1 
#define TTL                             32
#define PORT_RANGE                      65536
#define CNTLIMIT                        4
#define SLEEPTIME                       10000 /* usec */  // 10ms
#define DEFAULT_TIMEOUT                 100000 /* usec */ // 100ms

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
		return sip == t.sip && sport == t.sport && dip == t.sip && dport == t.dport;
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
	
 LNode(const T& e = T(), LNode* n = 0, LNode* p = 0)
	 : element(e), next(n), prev(p) {
		ts = 0;
		cnt = 0;
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
};

class DyscoHashOut;

class DyscoHashIn {
 public:
	DyscoTcpSession sub;
	DyscoTcpSession sup;
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
};

class DyscoHashOut {
 public:
	DyscoHashIn* dcb_in;
	DyscoTcpSession sub;
	DyscoTcpSession sup;

	uint32_t in_iseq;
	uint32_t in_iack;
	uint32_t out_iseq;
	uint32_t out_iack;
	uint32_t ack_delta;
	uint32_t seq_delta;
	uint32_t seq_cutoff;
	uint32_t ack_cutoff;

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
		state:7;
	
	uint32_t ack_ctr;

	DyscoControlMessage cmsg;
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
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_pen;
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash, DyscoTcpSessionEqualTo> hash_reconfig;

	//by devip
	unordered_map<uint32_t, mutex*> mutexes;
	unordered_map<uint32_t, LinkedList<Packet>* > retransmission_list;
	unordered_map<uint32_t, unordered_map<uint32_t, LNode<Packet>* >* > received_hash;
};

/*********************************************************************
 *
 *	Auxiliary methods
 *
 *********************************************************************/
inline bool isIP(Ethernet* eth) {
	return eth->ether_type.value() == Ethernet::Type::kIpv4;
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

inline bool isFromLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.value() == ntohl(cmsg->leftA);
}

inline bool isFromRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->src.value() == ntohl(cmsg->rightA);
}

inline bool isToLeftAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.value() == ntohl(cmsg->leftA);
}

inline bool isToRightAnchor(Ipv4* ip, DyscoControlMessage* cmsg) {
	return ip->dst.value() == ntohl(cmsg->rightA);
}

inline uint32_t hasPayload(Ipv4* ip, Tcp* tcp) {
	return ip->length.value() - (ip->header_length << 2) - (tcp->offset << 2);
}

inline uint32_t getValueToAck(Packet* pkt) {
	Ethernet* eth = pkt->head_data<Ethernet*>();
	Ipv4* ip = reinterpret_cast<Ipv4*>(eth + 1);
	Tcp* tcp = reinterpret_cast<Tcp*>(reinterpret_cast<uint8_t*>(ip) + (ip->header_length << 2));

	uint32_t toAck = tcp->seq_num.value() + hasPayload(ip, tcp);
	if(isTCPSYN(tcp))
	   toAck++;

	return toAck;
}

inline void out_hdr_rewrite(Ipv4* ip, Tcp* tcp, DyscoTcpSession* sub) {
	ip->src = be32_t(ntohl(sub->sip));
	ip->dst = be32_t(ntohl(sub->dip));
	tcp->src_port = be16_t(ntohs(sub->sport));
	tcp->dst_port = be16_t(ntohs(sub->dport));

	
}

inline void out_hdr_rewrite_csum(Ipv4* ip, Tcp* tcp, DyscoTcpSession* ss) {
	uint32_t incremental = 0;

	uint32_t new_src = ss->sip;
	uint32_t new_dst = ss->dip;
	uint16_t new_sport = ss->sport;
	uint16_t new_dport = ss->dport;

	incremental += bess::utils::ChecksumIncrement32(ip->src.raw_value(), new_src);
	incremental += bess::utils::ChecksumIncrement32(ip->dst.raw_value(), new_dst);

	*((uint32_t*)(&ip->src)) = 0;//new_src;
	*((uint32_t*)(&ip->dst)) = 0;//new_dst;
	
	ip->checksum = bess::utils::UpdateChecksumWithIncrement(ip->checksum, incremental);
	tcp->checksum = bess::utils::UpdateChecksumWithIncrement(tcp->checksum, incremental);

	incremental  = bess::utils::ChecksumIncrement16(tcp->src_port.raw_value(), new_src);
	incremental += bess::utils::ChecksumIncrement16(tcp->dst_port.raw_value(), new_dst);

	*((uint16_t*)(&tcp->src_port)) = new_sport;
	*((uint16_t*)(&tcp->dst_port)) = new_dport;
	
	tcp->checksum = bess::utils::UpdateChecksumWithIncrement(tcp->checksum, incremental);	
}

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

#endif //BESS_MODULES_DYSCOUTIL_H_
