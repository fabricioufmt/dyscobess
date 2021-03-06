/*
 *
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_user.go
 *
 *	User interface for the Dysco control protocol.
 *
 *	Author: Ronaldo A. Ferreira (raf@facom.ufms.br)
 *
 *
 *	This program is free software;  you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 *
 *	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *	WARRANTIES,  INCLUDING,  BUT  NOT   LIMITED  TO,  THE  IMPLIED
 *	WARRANTIES  OF MERCHANTABILITY  AND FITNESS  FOR A  PARTICULAR
 *	PURPOSE  ARE DISCLAIMED.   IN NO  EVENT SHALL  THE AUTHORS  OR
 *	CONTRIBUTORS BE  LIABLE FOR ANY DIRECT,  INDIRECT, INCIDENTAL,
 *	SPECIAL, EXEMPLARY,  OR CONSEQUENTIAL DAMAGES  (INCLUDING, BUT
 *	NOT LIMITED  TO, PROCUREMENT OF SUBSTITUTE  GOODS OR SERVICES;
 *	LOSS  OF  USE, DATA,  OR  PROFITS;  OR BUSINESS  INTERRUPTION)
 *	HOWEVER  CAUSED AND  ON ANY  THEORY OF  LIABILITY, WHETHER  IN
 *	CONTRACT, STRICT  LIABILITY, OR TORT (INCLUDING  NEGLIGENCE OR
 *	OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *	EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	The following packages are required:
 *	- github.com/vishvananda/go-netlink (Netlink library)
 *	- github.com/google/gopacket/pcap
 *
 */
package dysco

import (
	/*"bytes"*/
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/pcap"
	/*"github.com/vishvananda/go-netlink"*/
	"net"
)

const DYSCO_SERVER_PORT		= 2016
const DYSCO_MANAGEMENT_PORT	= 2017
const DYSCO_STATE_TRANSFER_PORT	= 2017
const DYSCO_NETLINK_USER	= 27

const (
	// Locking protocol
	DYSCO_REQUEST_LOCK = iota + 1
	DYSCO_ACK_LOCK
	DYSCO_NACK_LOCK
	
	// Reconfiguration
	DYSCO_SYN
	DYSCO_SYN_ACK
	DYSCO_ACK
	DYSCO_FIN
	DYSCO_FIN_ACK
	
	// Management
	DYSCO_POLICY
	DYSCO_REM_POLICY
	DYSCO_CLEAR
	DYSCO_CLEAR_ALL
	DYSCO_BUFFER_PACKET
	DYSCO_TCP_SPLICE
	DYSCO_COPY_STATE
	DYSCO_PUT_STATE
	DYSCO_STATE_TRANSFERRED
	DYSCO_ACK_ACK
	DYSCO_GET_MAPPING
	DYSCO_GET_REC_TIME
)

// States of a connection
const (
	DYSCO_ONE_PATH = iota
	DYSCO_ADDING_NEW_PATH
	DYSCO_ACCEPTING_NEW_PATH
	DYSCO_INITIALIZING_NEW_PATH
	DYSCO_MANAGING_TWO_PATHS
	DYSCO_FINISHING_OLD_PATH
	DYSCO_UNLOCKED
	DYSCO_LOCK_PENDING
	DYSCO_LOCKED
)

const (
	NOSTATE_TRANSFER = iota
	STATE_TRANSFER
)

// Constant for types of mappings. 
const (
	INPUT	= 1
	OUTPUT	= 2
)

type TcpSession struct {
	sip	net.IP
	dip	net.IP
	sport	uint16
	dport	uint16
}

type NextHop struct {
	ip	net.IP
	//mac	net.HardwareAddr
}

type ServiceChain struct {
	len	uint32
	ips	[]net.IP
}

type UserMessage struct {
	mtype	uint16
	body	[]byte
}

type ReconfigMessage struct {
     	my_sub	        TcpSession
	super		TcpSession
	leftSS		TcpSession	
	rightSS		TcpSession	
	leftA		net.IP
	rightA		net.IP

	sport		uint16		// filled by the kernel
	dport		uint16		// filled by the kernel

	leftIseq	uint32		// filled by the kernel
	leftIack	uint32		// filled by the kernel

	rightIseq	uint32		// filled by the kernel
	rightIack	uint32		// filled by the kernel

	seqCutoff	uint32		// filled by the kernel

	leftIts		uint32		// filled by the kernel
	leftItsr	uint32		// filled by the kernel

	leftIws		uint16		// filled by the kernel
	leftIwsr	uint16		// filled by the kernel
	
	sackOk		uint16		// filled by the kernel
	
	semantic	uint16		// 16 bits for alignment
	
	srcMB		net.IP		// source of state
	dstMB		net.IP		// destination of state

	chain		*ServiceChain
}

type TransferStateMessage struct {
	super		TcpSession
	src		net.IP
	dst		net.IP
	leftA		net.IP
	rightA		net.IP
}

type Filter	[]pcap.BPFInstruction

type NetlinkMessage struct {
	sc	*ServiceChain
	filter	Filter
}

type DyscoMapping struct {
	super	TcpSession
	sub	TcpSession
}

type DyscoMappingVector struct {
	len	uint16
	out	uint16
	vector	[]DyscoMapping
}



/*********************************************************************
 *
 *	TcpSession.String:
 *
 *********************************************************************/		
func (m *TcpSession) String() string {
	s := fmt.Sprintf("(%s,%d <-> %s, %d)", m.sip.String(), m.sport,
		m.dip.String(), m.dport)
	return s
}
/* TcpSession.String */


/*********************************************************************
 *
 *	ServiceChain.String:
 *
 *********************************************************************/		
func (m *ServiceChain) String() string {
	s := fmt.Sprintf("Len=%d", m.len)
	for i := 0; i < int(m.len); i++ {
		s = fmt.Sprintf("%s (%s)", s, m.ips[i].String())
	}
	return s
}
/* ServiceChain.String */


/*********************************************************************
 *
 *	NewTcpSession:
 *
 *********************************************************************/		
func NewTcpSession(src net.IP, dest net.IP, sport uint16, dport uint16) (s TcpSession) {
	s.sip   = src
	s.dip   = dest
	s.sport = sport
	s.dport = dport
	return 
}
/* NewTcpSession */


/*********************************************************************
 *
 *	NewUserMessage:
 *
 *********************************************************************/		
func NewUserMessage(t uint16, b []byte) (*UserMessage) {
	msg := &UserMessage {
		mtype:	t,
		body:	b,
	}
	return msg
}
/* NewUserMessage */


/*********************************************************************
 *
 *	NewReconfigMessage:
 *
 *********************************************************************/		
func NewReconfigMessage(ss, lSS, rSS TcpSession, l, r net.IP, sem uint16,
	sMB, dMB net.IP, sc *ServiceChain) (*ReconfigMessage) {
	
	msg := &ReconfigMessage {
	        my_sub:         ss,
		super:		ss,
		leftSS:		lSS,
		rightSS:	rSS,
		leftA:		l, 
		rightA:		r,
		sport:		0,
		dport:		0,
		leftIseq:	0,
		leftIack:	0,
		rightIseq:	0,
		rightIack:	0,
		seqCutoff:	0,
		leftIts:	0,
		leftItsr:	0,
		leftIws:	0,
		leftIwsr:	0,
		sackOk:		0,
		semantic:	sem,
		srcMB:		sMB,
		dstMB:		dMB,
		chain:		sc,
	}
	
	return msg
}
/* NewReconfigMessage */


/*********************************************************************
 *
 *	ReconfigMessage.Serializer:
 *
 *********************************************************************/		
func (self *ReconfigMessage) Serializer() (out []byte) {
        sub := self.my_sub.Serializer()
	ss  := self.super.Serializer()
	lSS := self.leftSS.Serializer()
	rSS := self.rightSS.Serializer()
	sc  := self.chain.Serializer()
	
	out  = make([]byte, len(sub)+len(ss)+len(lSS)+len(rSS)+len(sc)+56)
	copy(out[0:], sub)
	copy(out[12:], ss)
	copy(out[24:], lSS)
	copy(out[36:], rSS)
	copy(out[48:], self.leftA.To4())
	copy(out[52:], self.rightA.To4())
	
	binary.BigEndian.PutUint16(out[56:], self.sport)
	binary.BigEndian.PutUint16(out[58:], self.dport)
	binary.BigEndian.PutUint32(out[60:], self.leftIseq)
	binary.BigEndian.PutUint32(out[64:], self.leftIack)
	binary.BigEndian.PutUint32(out[68:], self.rightIseq)
	binary.BigEndian.PutUint32(out[72:], self.rightIack)
	binary.BigEndian.PutUint32(out[76:], self.seqCutoff)
	binary.BigEndian.PutUint32(out[80:], self.leftIts)
	binary.BigEndian.PutUint32(out[84:], self.leftItsr)
	binary.BigEndian.PutUint16(out[88:], self.leftIws)
	binary.BigEndian.PutUint16(out[90:], self.leftIwsr)
	binary.BigEndian.PutUint16(out[92:], self.sackOk)
	binary.BigEndian.PutUint16(out[94:], self.semantic)
	
	copy(out[96:], self.srcMB.To4())
	copy(out[100:], self.dstMB.To4())
	copy(out[104:], sc)
	
	return
}
/* ReconfigMessage.Serializer */


/*********************************************************************
 *
 *	ipV4:
 *
 *********************************************************************/		
func ipV4(b []byte) net.IP {
	return net.IPv4(b[0], b[1], b[2], b[3])
}
/* ipV4 */


/*********************************************************************
 *
 *	ServiceChain.Serializer:
 *
 *********************************************************************/		
func (self ServiceChain) Serializer() (out []byte) {
	sz := 4 + int(self.len)*4;
	out = make([]byte, sz)
	// FIXME: Change to big endian
	binary.BigEndian.PutUint32(out[0:], self.len) 
	j := 4
	for i := 0; i < int(self.len); i++ {
		j += copy(out[j:], self.ips[i].To4())
		//j += copy(out[j:], self.nh[i].mac)
	}
	return
}
/* ServiceChain.Serializer */


/*********************************************************************
 *
 *	TcpSession.Serializer:
 *
 *********************************************************************/		
func (self TcpSession) Serializer() (out []byte) {
	out = make([]byte, 12)
	copy(out[0:], self.sip.To4())
	copy(out[4:], self.dip.To4())
	binary.BigEndian.PutUint16(out[8:], self.sport)
	binary.BigEndian.PutUint16(out[10:], self.dport)
	return
}
/* TcpSession.Serializer */


/*********************************************************************
 *
 *	CreateSC:
 *
 *********************************************************************/		
func CreateSC(sc_len int, args []string) (*ServiceChain, error) {
	var sc ServiceChain
	sc.len = uint32(sc_len)
	sc.ips  = make([]net.IP, sc_len)
	for i := 0; i < sc_len; i++ {
		sc.ips[i] = net.ParseIP(args[i])
	}
	return &sc, nil
}
/* CreateSc */


/*********************************************************************
 *
 *	CreateSCUser:
 *
 *********************************************************************/
 /*
func CreateSCUser(sc_len int, args []string) (*ServiceChain, error) {
	var sc ServiceChain
	sc.len = uint16(sc_len)
	sc.pos = uint16(0)
	sc.nh  = make([]NextHop, sc_len)
	for i := 0; i < sc_len; i++ {
		sc.nh[i].ip  = net.ParseIP(args[i])
	}
	return &sc, nil
}
*/
/* CreateSCUSER */

