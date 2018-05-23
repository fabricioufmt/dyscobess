#ifndef BESS_MODULES_DYSCOUTIL_H_
#define BESS_MODULES_DYSCOUTIL_H_

#include <string>
#include <stdint.h>
//#include <arpa/inet.h>
#include <unordered_map>
#include <rte_hash_crc.h>

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/ether.h"
#include "../utils/endian.h"
#include "../utils/checksum.h"

#include "dysco_policies.h"

using std::mutex;
using std::string;
using std::size_t;
using std::unordered_map;

using bess::Packet;
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;


/*********************************************************************
 *
 *	DEBUG
 *
 *********************************************************************/
#define DEBUG 1


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

#define TTL                             32
#define PORT_RANGE                      65536
#define CNTLIMIT                        3

/*********************************************************************
 *
 *	Auxiliary methods
 *
 *********************************************************************/



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
class Node {
public:
	T element;
	Node* next;
	Node* prev;
	uint64_t ts;
	uint32_t cnt;
	
	Node(const T& e, Node* n = 0, Node* p = 0)
		: element(e), next(n), prev(p), cnt(0), ts(0) {
	}
	
	~Node() {
		if(prev)
			prev->next = next;

		if(next)
			next->prev = prev;
	}
};

template <typename T>
class LinkedList {
private:
	Node<T>* head;
	Node<T>* tail;

public:
	LinkedList() {
		head = new Node<T>();
		tail = new Node<T>();

		head->next = tail;
		tail->prev = head;
	}

	~LinkedList() {
		clear();
		
		delete head;
		delete tail;
	}

	Node<T>* getHead() {
		return head;
	}

	Node<T>* getTail() {
		return tail;
	}
	
	void clear() {
		while(tail->prev != head) {
			Node<T>* toRemove = tail->prev;
			tail->prev = toRemove->prev;
			
			delete toRemove;
		}
	}

	bool remove(Node<T>* node) {
		if(!node)
			return false;

		delete node;

		return true;
	}

	Node<T>* insertHead(T& element) {
		Node<T>* node = new Node<T>(element);

		head->next->prev = node;
		node->next = head->next;
		node->prev = head;
		head->next = node;

		return node;
	}

	Node<T>* insertTail(T& element) {
		Node<T>* node = new Node<T>(element);

		tail->prev->next = node;
		node->prev = tail->prev;
		node->next = tail;
		tail->prev = node;
		
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

	//uint8_t padding;
	uint8_t is_reconfiguration:1,
		state:7;

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

	//uint8_t state;
	uint8_t is_reconfiguration:1,
		state:7;
	
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
	uint8_t padding;
	
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
	uint32_t devip;
	uint32_t dysco_tag;
	DyscoPolicies policies;

	unordered_map<uint32_t, DyscoHashOut*> hash_pen_tag;
	unordered_map<DyscoTcpSession, DyscoHashIn*, DyscoTcpSessionHash> hash_in;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_out;
	unordered_map<DyscoTcpSession, DyscoHashOut*, DyscoTcpSessionHash> hash_pen;
	unordered_map<DyscoTcpSession, DyscoCbReconfig*, DyscoTcpSessionHash> hash_reconfig;

	//by devip
	unordered_map<uint32_t, mutex> mutexes;
	unordered_map<uint32_t, LinkedList<bess::Packet> > retransmission_list;
	unordered_map<uint32_t, unordered_map<uint32_t, Node<bess::Packet>* > > received_hash;
};

#endif //BESS_MODULES_DYSCOUTIL_H_
