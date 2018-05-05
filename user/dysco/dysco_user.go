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
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/go-netlink"
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
	len	uint16
	pos	uint16
	nh	[]NextHop
}

type UserMessage struct {
	mtype	uint16
	body	[]byte
}

type ReconfigMessage struct {
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
 *	Filter.Serializer:
 *
 *********************************************************************/		
func (bpf Filter) Serializer() (out []byte) {
	f_len := len(bpf)
	if f_len < 1 {
		return nil
	}
	
	out = make([]byte, 8*f_len + 2)
	binary.LittleEndian.PutUint16(out, uint16(f_len))
	for i := 0; i < f_len; i++ {
		j := i*8 + 2
		binary.LittleEndian.PutUint16(out[j:], bpf[i].Code)
		out[j+2] = bpf[i].Jt
		out[j+3] = bpf[i].Jf
		binary.LittleEndian.PutUint32(out[j+4:], bpf[i].K)
	}	
	return
}
/* Filter.Serializer */


/*********************************************************************
 *
 *	filterUnmarshal:
 *
 *********************************************************************/		
func filterUnmarshal(buf []byte) (out Filter) {
	f_len := binary.LittleEndian.Uint16(buf[0:])
	out = make([]pcap.BPFInstruction, f_len)
	for i:= 0; i < int(f_len); i++ {
		j := i*8 + 2
		out[i].Code = binary.LittleEndian.Uint16(buf[j:])
		out[i].Jt   = buf[j+2]
		out[i].Jf   = buf[j+3]
		out[i].K    = binary.LittleEndian.Uint32(buf[j+4:])
	}
	return
}
/* filterUnmarshal */


/*********************************************************************
 *
 *	NetlinkMessage.Marshalnetlink:
 *
 *********************************************************************/		
func (self NetlinkMessage) MarshalNetlink() (out []byte, err error) {
	if self.sc != nil {
		sc  := self.sc.Serializer()
		bpf := self.filter.Serializer()
		out = bytes.Join([][]byte{sc, bpf}, []byte{})
	} else {
		out = []byte{}
	}	
	return
}
/* MarshalNetlink */


/*********************************************************************
 *
 *	msgSerializer:
 *
 *********************************************************************/		
func msgSerializer(self NetlinkMessage) (out []byte, err error) {
	sc  := self.sc.Serializer()
	bpf := self.filter.Serializer()
	out = bytes.Join([][]byte{sc, bpf}, []byte{})
	return
}
/* msgSerializer */


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
	s := fmt.Sprintf("Len=%d Pos=%d", m.len, m.pos)
	for i := 0; i < int(m.len); i++ {
		s = fmt.Sprintf("%s (%s)", s, m.nh[i].ip.String())
	}
	return s
}
/* ServiceChain.String */


/*********************************************************************
 *
 *	UserMessage.String:
 *
 *********************************************************************/		
func (m *UserMessage) String() string {
	var t_s string
	switch m.mtype {
	case DYSCO_SYN:
		msg := unMarshalReconfigMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_SYN\n\tsuper=%s "+
			"\n\tleftSS=%s\n\trightSS=%s "+
			"\n\tleftA=%s \n\trightA=%s \n\tchain=(%s)",
			msg.super.String(),
			msg.leftSS.String(),
			msg.rightSS.String(),
			msg.leftA.String(),
			msg.rightA.String(),
			msg.chain.String())
		
	case DYSCO_SYN_ACK:
		msg := unMarshalReconfigMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_SYN_ACK\n\tsuper=%s "+
			"\n\tleftA=%s \n\trightA=%s \n\tchain=(%s)",
			msg.super.String(),
			msg.leftA.String(),
			msg.rightA.String(),
			msg.chain.String())
		
	case DYSCO_ACK:
		msg := unMarshalReconfigMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_ACK\n\tsuper=%s "+
			"\n\tleftA=%s \n\trightA=%s \n\tchain=(%s)",
			msg.super.String(),
			msg.leftA.String(),
			msg.rightA.String(),
			msg.chain.String())
		
	case DYSCO_FIN:
		msg := unMarshalReconfigMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_FIN\n\tsuper=%s "+
			"\n\tleftA=%s \n\trightA=%s \n\tchain=(%s)",
			msg.super.String(),
			msg.leftA.String(),
			msg.rightA.String(),
			msg.chain.String())

	case DYSCO_STATE_TRANSFERRED:
		msg := unMarshalReconfigMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_STATE_TRANSFERRED"+
			"\n\tsuper=%s\n\tleftA=%s\n\trightA=%s\n\tchain=(%s)",
			msg.super.String(),
			msg.leftA.String(),
			msg.rightA.String(),
			msg.chain.String())

	case DYSCO_COPY_STATE:
		msg := unMarshalTransferStateMessage(m.body)
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_COPY_STATE\n\tsuper=%s "+
			"\n\tsrc=%s\n\tdst=%s\n\tleftA=%s\n\trightA=%s",
			msg.super.String(),
			msg.src.String(),
			msg.dst.String(),
			msg.leftA.String(),
			msg.rightA.String())

	case DYSCO_GET_MAPPING:
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_GET_MAPPING\n")
		
	case DYSCO_GET_REC_TIME:
		t_s = fmt.Sprintf("\n\tmtype=DYSCO_GET_REC_TIME\n")
	}
	return t_s
}
/* UserMessage.String */


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
 *	NewTransferStateMessage:
 *
 *********************************************************************/		
func NewTransferStateMessage(ss TcpSession, s, d, l, r net.IP) (*TransferStateMessage) {
	msg := &TransferStateMessage {
		super:	ss,
		src:	s,
		dst:	d,
		leftA:	l,
		rightA:	r,
	}
	return msg
}
/* NewTransferStateMessage */


/*********************************************************************
 *
 *	TransferStateMessage.Serializer:
 *
 *********************************************************************/		
func (self *TransferStateMessage) Serializer() (out []byte) {
	ss := self.super.Serializer()
	out = make([]byte, len(ss)+16)
	copy(out[0:], ss)
	copy(out[12:], self.src.To4())
	copy(out[16:], self.dst.To4())
	copy(out[20:], self.leftA.To4())
	copy(out[24:], self.rightA.To4())
	return out
}
/* TransferStateMessage.Serializer */


/*********************************************************************
 *
 *	unMarshalTransferStateMessage:
 *
 *********************************************************************/		
func unMarshalTransferStateMessage(buf []byte) (*TransferStateMessage) {
	msg := &TransferStateMessage {}
	msg.super  = tcpSessionUnmarshal(buf[0:])
	msg.src    = ipV4(buf[12:])
	msg.dst    = ipV4(buf[16:])
	msg.leftA  = ipV4(buf[20:])
	msg.rightA = ipV4(buf[24:])
	return msg
}
/* unMarshalTransferStateMessage */


/*********************************************************************
 *
 *	NewReconfigMessage:
 *
 *********************************************************************/		
func NewReconfigMessage(ss, lSS, rSS TcpSession, l, r net.IP, sem uint16,
	sMB, dMB net.IP, sc *ServiceChain) (*ReconfigMessage) {
	
	msg := &ReconfigMessage {
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
 *	NewReconfigMessageRaw:
 *
 *********************************************************************/		
func NewReconfigMessageRaw(buf []byte) (*ReconfigMessage, string) {
	leftSS  := tcpSessionUnmarshalRaw(buf)
	rightSS := tcpSessionUnmarshalRaw(buf[12:])

	chain := []string{leftSS.sip.String(), rightSS.dip.String()}
	sc, _ := CreateSCUser(2, chain)

	rec := NewReconfigMessage(leftSS, leftSS, rightSS,
		leftSS.sip, rightSS.dip,
		NOSTATE_TRANSFER, net.ParseIP("0.0.0.0"),
		net.ParseIP("0.0.0.0"), sc)
	return rec, leftSS.sip.String()
}
/* NewReconfigMessageRaw */


/*********************************************************************
 *
 *	ReconfigMessage.Serializer:
 *
 *********************************************************************/		
func (self *ReconfigMessage) Serializer() (out []byte) {
	ss  := self.super.Serializer()
	lSS := self.leftSS.Serializer()
	rSS := self.rightSS.Serializer()
	sc  := self.chain.Serializer()
	
	out  = make([]byte, len(ss)+len(lSS)+len(rSS)+len(sc)+56)
	copy(out[0:], ss)
	copy(out[12:], lSS)
	copy(out[24:], rSS)
	copy(out[36:], self.leftA.To4())
	copy(out[40:], self.rightA.To4())
	
	binary.BigEndian.PutUint16(out[44:], self.sport)
	binary.BigEndian.PutUint16(out[46:], self.dport)
	binary.BigEndian.PutUint32(out[48:], self.leftIseq)
	binary.BigEndian.PutUint32(out[52:], self.leftIack)
	binary.BigEndian.PutUint32(out[56:], self.rightIseq)
	binary.BigEndian.PutUint32(out[60:], self.rightIack)
	binary.BigEndian.PutUint32(out[64:], self.seqCutoff)
	binary.BigEndian.PutUint32(out[68:], self.leftIts)
	binary.BigEndian.PutUint32(out[72:], self.leftItsr)
	binary.BigEndian.PutUint16(out[76:], self.leftIws)
	binary.BigEndian.PutUint16(out[78:], self.leftIwsr)
	binary.BigEndian.PutUint16(out[80:], self.sackOk)
	binary.BigEndian.PutUint16(out[82:], self.semantic)
	
	copy(out[84:], self.srcMB.To4())
	copy(out[88:], self.dstMB.To4())
	copy(out[92:], sc)
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
 *	scUnmarshal:
 *
 *********************************************************************/		
func scUnmarshal(buf []byte) (*ServiceChain, int) {
	sc := &ServiceChain{}
	//fmt.Println("service chain buf len:", len(buf))
	sc.len = binary.LittleEndian.Uint16(buf[0:])
	sc.pos = binary.LittleEndian.Uint16(buf[2:])
	sc.nh = make([]NextHop, sc.len)
	j := 4
	for i := 0; i < int(sc.len); i++ {
		sc.nh[i].ip  = ipV4(buf[j:])
		//sc.nh[i].mac = buf[j+4:j+10]
		//j += 10
		j += 4
	}
	return sc, j
}
/* scUnmarshal */


/*********************************************************************
 *
 *	tcpSessionUnmarshal:
 *
 *********************************************************************/		
func tcpSessionUnmarshal(buf []byte) (msg TcpSession) {
	msg.sip   = ipV4(buf[0:])
	msg.dip   = ipV4(buf[4:])
	msg.sport = binary.BigEndian.Uint16(buf[8:])
	msg.dport = binary.BigEndian.Uint16(buf[10:])
	return 
}
/* tcpSessionUnmarshal */


/*********************************************************************
 *
 *	tcpSessionUnmarshalRaw:
 *
 *********************************************************************/		
func tcpSessionUnmarshalRaw(buf []byte) (msg TcpSession) {
	msg.sip   = ipV4(buf[0:])
	msg.sport = binary.BigEndian.Uint16(buf[4:])
	msg.dip   = ipV4(buf[6:])
	msg.dport = binary.BigEndian.Uint16(buf[10:])
	return 
}
/* tcpSessionUnmarshalRaw */


/*********************************************************************
 *
 *	TcpSessionUnmarshal:
 *
 *********************************************************************/		
func TcpSessionUnmarshal(buf []byte) (TcpSession) {
	return tcpSessionUnmarshal(buf)
}
/* TcpSessionUnmarshal */


/*********************************************************************
 *
 *	UnMarshalUserMessage:
 *
 *********************************************************************/		
func UnMarshalUserMessage(buf []byte) (msg UserMessage) {
	msg.mtype = binary.LittleEndian.Uint16(buf[0:])
	msg.body  = buf[2:]	
	return
}
/* UnMarshalUserMessage */


/*********************************************************************
 *
 *	unMarshalReconfigMessage:
 *
 *********************************************************************/		
func unMarshalReconfigMessage(buf []byte) (msg *ReconfigMessage) {
	msg = &ReconfigMessage{}
	
	msg.super     = tcpSessionUnmarshal(buf[0:])
	msg.leftSS    = tcpSessionUnmarshal(buf[12:])
	msg.rightSS   = tcpSessionUnmarshal(buf[24:])
	
	msg.leftA     = ipV4(buf[36:])
	msg.rightA    = ipV4(buf[40:])
	
	msg.sport     = binary.BigEndian.Uint16(buf[44:])
	msg.dport     = binary.BigEndian.Uint16(buf[46:])
	msg.leftIseq  = binary.BigEndian.Uint32(buf[48:])
	msg.leftIack  = binary.BigEndian.Uint32(buf[52:])
	msg.rightIseq = binary.BigEndian.Uint32(buf[56:])
	msg.rightIack = binary.BigEndian.Uint32(buf[60:])
	msg.seqCutoff = binary.BigEndian.Uint32(buf[64:])
	msg.leftIts   = binary.BigEndian.Uint32(buf[68:])
	msg.leftItsr  = binary.BigEndian.Uint32(buf[72:])
	msg.leftIws   = binary.BigEndian.Uint16(buf[76:])
	msg.leftIwsr  = binary.BigEndian.Uint16(buf[78:])
	msg.sackOk    = binary.BigEndian.Uint16(buf[80:])
	msg.semantic  = binary.BigEndian.Uint16(buf[82:])
	
	msg.srcMB     = ipV4(buf[84:])
	msg.dstMB     = ipV4(buf[88:])
	
	sc, _        := scUnmarshal(buf[92:])
	msg.chain     = sc
	return
}
/* unMarshalReconfigMessage */


/*********************************************************************
 *
 *	ServiceChain.Serializer:
 *
 *********************************************************************/		
func (self ServiceChain) Serializer() (out []byte) {
	sz := 4 + int(self.len)*4;
	out = make([]byte, sz)
	// FIXME: Change to big endian
	binary.LittleEndian.PutUint16(out[0:], self.len) 
	binary.LittleEndian.PutUint16(out[2:], self.pos)
	j := 4
	for i := 0; i < int(self.len); i++ {
		j += copy(out[j:], self.nh[i].ip.To4())
		//j += copy(out[j:], self.nh[i].mac)
	}
	return
}
/* ServiceChain.Serializer */


/*********************************************************************
 *
 *	CreateFilter:
 *
 *********************************************************************/		
func CreateFilter(filter string) (bpf Filter, err error) {
	handle, err := pcap.OpenDead(pcap.DLT_EN10MB, 65536)
	if err != nil {
		fmt.Println("Could not open pcap device dead", err)
		return nil, err
	}
	
	bpf, err = handle.CompileBPFFilter(filter)
	if err != nil {
		fmt.Println("Error compiling filter ", filter, err)
		return nil, err
	}
	return
}
/* CreateFilter */


/*********************************************************************
 *
 *	NewNetlinkMessage:
 *
 *********************************************************************/		
func NewNetlinkMessage(mtype netlink.MessageType, sc *ServiceChain,
	bpf Filter) (*netlink.Message, error) {
	var out NetlinkMessage
	
	out.sc      = sc
	out.filter  = bpf
	nlmsg, err := netlink.NewMessage(mtype, 0, out)
	return nlmsg, err
}
/* NewNetlinkMessage */


/*********************************************************************
 *
 *	NewNetlinkMessageNotify:
 *
 *********************************************************************/		
func NewNetlinkMessageNotify(cmd netlink.MessageType) (*netlink.Message, error) {
	var out NetlinkMessage

	out.sc = nil
	out.filter = nil
	nlmsg, err := netlink.NewMessage(cmd, 0, out)
	return nlmsg, err
}
/* NewNetlinkMessageNotify */


/*********************************************************************
 *
 *	NewNetlinkMessageRaw:
 *
 *********************************************************************/		
func NewNetlinkMessageRaw(buf []byte) (*netlink.Message, error) {
	var out NetlinkMessage
	sc, sc_len := scUnmarshal(buf)
	out.sc = sc
	out.filter =  filterUnmarshal(buf[sc_len:])
	nlmsg, err := netlink.NewMessage(DYSCO_POLICY, 0, out)
	return nlmsg, err
}
/* NewNetlinkMessageRaw */


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
 *	UserMessage.Serializer:
 *
 *********************************************************************/		
func (self *UserMessage) Serializer() (out []byte) {
	mtype := make([]byte, 2)
	binary.LittleEndian.PutUint16(mtype[0:], self.mtype)
	out = bytes.Join([][]byte{mtype, self.body}, []byte{})
	return
}
/* UserMessage.Serializer */


/*********************************************************************
 *
 *	CreateSC:
 *
 *********************************************************************/		
func CreateSC(sc_len int, args []string) (*ServiceChain, error) {
	var sc ServiceChain
	sc.len = uint16(sc_len)
	sc.pos = uint16(0)
	sc.nh  = make([]NextHop, sc_len)
	for i := 0; i < sc_len; i++ {
		sc.nh[i].ip  = net.ParseIP(args[i])
		
		/* mac is no longer needed. using arp now in the kernel.
		mac, err := net.ParseMAC(args[i+1])
		if err != nil {
			return nil, err
		}
		sc.nh[j].mac =  mac
		*/
	}
	return &sc, nil
}
/* CreateSc */


/*********************************************************************
 *
 *	CreateSCUser:
 *
 *********************************************************************/		
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
/* CreateSCUSER */

