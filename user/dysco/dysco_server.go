/*
 *
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_server.go
 *
 *	Functions for the server part of the control protocol.
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
 *	Part of this code was borrowed from github.com/reusee.
 *	The following packages are required:
 *	- github.com/vishvananda/go-netlink (Netlink library)
 *	- github.com/reusee/closer
 *	- github.com/reusee/inf-chan
 *
 */
package dysco

import (
	"encoding/binary"
	"fmt"
	"github.com/reusee/closer"
	"github.com/vishvananda/go-netlink"	
	ic "github.com/reusee/inf-chan"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type  Server struct {
	closer.Closer
	*Logger	
	udpConn		*net.UDPConn
	udpConnClosed	bool
	newConnsIn	chan *Conn
	NewConns	chan *Conn
}

var MyIfaces		map[string]int

var MyConnections	map[*Conn]*Conn
var connectionsMutex	sync.Mutex

var netlinkHandler	*netlink.Handler

var lockedSessions	map[string]bool
var lockedMutex		sync.Mutex
/* */


/*********************************************************************
 *
 *	Server.SetInterfaces:
 *
 *********************************************************************/		
func (s *Server) SetInterfaces(ifaces []string) {
	
	MyIfaces = make(map[string]int)
	for i, v := range ifaces {
		MyIfaces[v] = i
	}
}
/* Server.SetInterfaces */


/*********************************************************************
 *
 *	Server.SetTimeOut:
 *
 *********************************************************************/		
func (s *Server) SetTimeOut(to time.Duration) {
	
	dysco_timeout = to
}
/* Server.SetTimeOut */


/*********************************************************************
 *
 *	Server.OpenNetlink:
 *
 *********************************************************************/		
func (s *Server) OpenNetlink() {
	
	nlsock, err := netlink.Dial(DYSCO_NETLINK_USER)
	if err != nil {
		fmt.Println("error opening netlink socket %v", err)
		os.Exit(1)
	}
	netlinkHandler = netlink.NewHandler(nlsock)
	ec := make(chan error)
	go netlinkHandler.StartDysco(ec)
}
/* Server.OpenNetlink */


/*********************************************************************
 *
 *	Server.readPacket:
 *
 *********************************************************************/		
func (s *Server) readPacket(packetData []byte) (uint32, uint32, byte, []byte) {
	
	serial, ackSerial, flag, data := readPacket(packetData)
	return serial, ackSerial, flag, data
}
/* Server.readPacket */


/*********************************************************************
 *
 *	Server.newConn:
 *
 *********************************************************************/		
func (s *Server) newConn(conns map[string]*Conn, remoteAddr *net.UDPAddr,
			 packetData []byte) {
	
	s.readPacket(packetData)
	conn := makeConn("Server", s.udpConn)
	conn.writeUDP = func(data []byte) error {
		_, err := s.udpConn.WriteToUDP(data, remoteAddr)
		return err
	}
	//conn.ackSerial = serial+1
	conn.ackSerial = 0
	conns[remoteAddr.String()] = conn
	conn.OnClose(func() {
		delete(conns, remoteAddr.String())
	})
	s.newConnsIn <- conn
	go handleUserMessage(conn)	
	go conn.start()
}
/* Server.newConn */


/*********************************************************************
 *
 *	NewUDPServer:
 *
 *********************************************************************/		
func NewUDPServer(addrStr string) (*Server, error) {
	
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	server := &Server {
		Logger:		newLogger(),
		udpConn:	udpConn,
		newConnsIn:	make(chan *Conn),
		NewConns:	make(chan *Conn),
	}
	
	MyConnections = make(map[*Conn]*Conn)
	ic.Link(server.newConnsIn, server.NewConns)
	server.OnClose(func() {
		server.udpConnClosed = true
		udpConn.Close()
		close(server.newConnsIn)
	})

	lockedSessions = make(map[string]bool)
	
	go func() { // listen
		conns := make(map[string]*Conn)
		for {
			packetData := make([]byte, 1500)
			n, addr, err := udpConn.ReadFromUDP(packetData)
			if err != nil {
				if server.udpConnClosed {
					return
				} else {
					log.Fatalf("server read error %v", err)
				}
			}
			packetData = packetData[:n]
			
			key := addr.String()
			conn, ok := conns[key]
			if !ok { //new connection
				server.newConn(conns, addr, packetData)
				conn, _ = conns[key]
				conn.incomingPacketsIn <- packetData
			} else {
				conn.incomingPacketsIn <- packetData
			}
		}
	}()
	return server, nil
}
/* NewUDPServer */


/*********************************************************************
 *
 *	dealRLock: We explore the map feature  of Go, so we do not use
 *	the  state  variables in  the  model.   This really  needs  be
 *	revised as we work on  the deployment of Dysco.  The prototype
 *	currently does not cover the  messages in the old path because
 *	we  do  not  evaluate simultaneous  reconfigurations  for  the
 *	paper.  These features  will be  added in  future versions  of
 *	Dysco, as we work on its deployment.
 *
 *********************************************************************/		
func dealRLock(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)

	lockedMutex.Lock()
	_, ok := lockedSessions[msg.super.String()]
	if ok {
		lockedMutex.Unlock()
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_NACK_LOCK, b)
		c.Send(nm.Serializer())
		return
	}
	lockedSessions[msg.super.String()] = true
	lockedMutex.Unlock()
	
	_, ok = MyIfaces[msg.rightA.String()]
	if ok {
		// I am the right anchor. Build and send the grant lock back.
		fmt.Println("I am the right anchor")
		//m.mtype = DYSCO_SYN_ACK
		msg.chain.pos--
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_ACK_LOCK, b)
		c.Send(nm.Serializer())
		
	} else {
		// I am not the right anchor. Just forward the message.
		msg.chain.pos++
		nh := msg.chain.nh[msg.chain.pos].ip.To4().String()
		fmt.Println("I am NOT the right anchor. Next hop", msg.rightA.String(), nh)
		str := fmt.Sprintf("%s:%d", nh, DYSCO_SERVER_PORT)
		client, err := NewClient(str)
		if err != nil {
			log.Fatal("could not create Dysco client", str)
			os.Exit(1)
		}
		
		connectionsMutex.Lock()
		MyConnections[client] = c
		MyConnections[c] = client
		connectionsMutex.Unlock()
		
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_REQUEST_LOCK, b)
		client.Send(nm.Serializer())
	}
}
/* dealRLock */


/*********************************************************************
 *
 *	dealAckLock: The  same comment in dealRLock  applies here.  We
 *	need to reimplement this function for the deployment.
 *
 *********************************************************************/		
func dealAckLock(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)
	_, ok := MyIfaces[msg.leftA.String()]
	if ok {
		fmt.Println("I am the left anchor and received the ACK_LOCK")
		msg.chain.pos++
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_SYN, b)
		c.Send(nm.Serializer())
		
	} else {
		msg.chain.pos--
		connectionsMutex.Lock()
		srv, ok := MyConnections[c]
		connectionsMutex.Unlock()
		if !ok {
			fmt.Println("could not find the server of this client in dealAckLock")
			os.Exit(1)
		}
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_ACK_LOCK, b)
		srv.Send(nm.Serializer())
	}
}
/* dealAckLock */


/*********************************************************************
 *
 *	dealNAckLock: The same comment  in dealRLock applies here.  We
 *	need to reimplement this function for the deployment.
 *
 *********************************************************************/		
func dealNAckLock(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)
	_, ok := MyIfaces[msg.leftA.String()]
	if ok {
		fmt.Println("I am the left anchor and received the NACK_LOCK")
	} else {
		msg.chain.pos--
		connectionsMutex.Lock()
		srv, ok := MyConnections[c]
		connectionsMutex.Unlock()
		if !ok {
			fmt.Println("could not find the server of this client in dealAckLock")
			os.Exit(1)
		}
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_NACK_LOCK, b)
		srv.Send(nm.Serializer())
	}
}
/* dealNackLock */


/*********************************************************************
 *
 *	dealRsyn:  handles  the   reconfiguration  SYN  messages.   We
 *	simplified its  implementation, so  it basically  forwards the
 *	control messages from hop to  hop along the service chain. The
 *	kernel module  intercepts the  control messages and  write the
 *	necessary session information. For the deployment of Dysco, we
 *	need  to decide  if  the kernel  module  should intercept  the
 *	control packets or  we should use netlink. In  fact, we really
 *	need to revist the use of UDP vs TCP for the reconfiguration.
 *
 *********************************************************************/		
func dealRsyn(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)
	_, ok := MyIfaces[msg.rightA.String()]
	if ok {
		// I am the right anchor. Build and send the ack back.
		fmt.Println("I am the right anchor")
		//m.mtype = DYSCO_SYN_ACK
		msg.chain.pos--
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_SYN_ACK, b)
		c.Send(nm.Serializer())
		
	} else {
		// I am not the right anchor. Just forward the message.
		msg.chain.pos++
		nh := msg.chain.nh[msg.chain.pos].ip.To4().String()
		fmt.Println("I am NOT the right anchor. Next hop", msg.rightA.String(), nh)
		str := fmt.Sprintf("%s:%d", nh, DYSCO_SERVER_PORT)
		client, err := NewClient(str)
		if err != nil {
			log.Fatal("could not create Dysco client", str)
			os.Exit(1)
		}
		
		connectionsMutex.Lock()
		MyConnections[client] = c
		MyConnections[c] = client
		connectionsMutex.Unlock()
		
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_SYN, b)
		client.Send(nm.Serializer())
	}
}
/* dealRsyn */


/*********************************************************************
 *
 *	dealSynAck: handles the reconfiguration SYN_ACK messages.  The
 *	current implementation  follows the  pattern described  in the
 *	comments for dealRsyn.
 *
 *********************************************************************/		
func dealSynAck(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)
	_, ok := MyIfaces[msg.leftA.String()]
	if ok {
		fmt.Println("I am the left anchor and received the SYN_ACK")
		//m.mtype = DYSCO_ACK
		msg.chain.pos++
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_ACK, b)
		c.Send(nm.Serializer())
		fmt.Println("Left anchor: semantic=", msg.semantic)
		if msg.semantic == STATE_TRANSFER {
			addrSrv := fmt.Sprintf("%s:%d", msg.srcMB.String(), DYSCO_SERVER_PORT)
			client, err := NewClient(addrSrv)
			if err != nil {
				fmt.Println("could not create Dysco client for state transfer")
				return
			}
			fmt.Println("Sending state transfer to ", addrSrv, msg.srcMB, msg.dstMB)
			copy_msg := NewTransferStateMessage(msg.super,
				msg.srcMB, msg.dstMB, msg.leftA, msg.rightA)
			dysco_msg := NewUserMessage(DYSCO_COPY_STATE, copy_msg.Serializer())
			buf := dysco_msg.Serializer()
			client.Send(buf)
		}
		
	} else {
		msg.chain.pos--
		connectionsMutex.Lock()
		srv, ok := MyConnections[c]
		connectionsMutex.Unlock()
		if !ok {
			fmt.Println("could not find the server of this client in dealSynAck")
			os.Exit(1)
		}
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_SYN_ACK, b)
		srv.Send(nm.Serializer())
	}
}
/* dealSynAck */


/*********************************************************************
 *
 *	dealAck:  handles  the   reconfiguration  ACK  messages.   The
 *	current implementation  follows the  pattern described  in the
 *	comments for dealRsyn.
 *
 *********************************************************************/		
func dealAck(c *Conn, m *UserMessage) {
	
	msg := unMarshalReconfigMessage(m.body)
	_, ok := MyIfaces[msg.rightA.String()]
	if ok {
		fmt.Println("I am the right anchor. Reconfiguration done.")
	} else {
		// I am not the right anchor. Just forward the message.
		msg.chain.pos++		
		connectionsMutex.Lock()		
		client, ok := MyConnections[c]
		connectionsMutex.Unlock()
		if !ok {
			fmt.Println("Could not find the client of this server in dealAck")
			os.Exit(1)
		}
		b := msg.Serializer()
		nm := NewUserMessage(DYSCO_ACK, b)
		client.Send(nm.Serializer())
	}
}
/* dealAck */


/*********************************************************************
 *
 *	dealFin: FIN  messages are  not currently implemented  as they
 *	are sent in the old path.
 *
 *********************************************************************/		
func dealFin(c *Conn, m *UserMessage) {	
}
/* dealFin */


/*********************************************************************
 *
 *	dealPolicy: receives  a policy from a  control application and
 *	forwards it to the kernel module using netlink.
 *
 *********************************************************************/		
func dealPolicy(c *Conn, m *UserMessage) {
	
	nlmsg, err := NewNetlinkMessageRaw(m.body)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	_, err = netlinkHandler.Query(*nlmsg, 1)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
	}
}
/* dealPolicy */


/*********************************************************************
 *
 *	UnmarshalMapping: shows the current  input and output mappings
 *	between  TCP  sessions  and  subsessions in  the  kernel.   It
 *	currently prints on the screen  instead of sending back to the
 *	client that requested the mappings. 
 *
 *********************************************************************/		
func UnmarshalMapping(body []byte) {
	
	len := binary.BigEndian.Uint16(body[0:])
	out := binary.BigEndian.Uint16(body[2:])

	fmt.Println("UnmarshalMapping: out =", out, " len =", len)
	buf := body[4:]
	if out > 0 {
		fmt.Printf("\n-----------------------Output Mapping-----------------------")
	}
	for i := 0; i < int(out); i++ {
		in_s  := tcpSessionUnmarshal(buf[0:])
		out_s := tcpSessionUnmarshal(buf[12:])
		buf = buf[24:]
		fmt.Printf("\nsuper(%s) sub(%s)", in_s.String(), out_s.String());
	}

	if len > out {
		fmt.Printf("\n\n-----------------------Input  Mapping-----------------------")
	}
	for i := out; i < len; i++ {
		in_s  := tcpSessionUnmarshal(buf[0:])
		out_s := tcpSessionUnmarshal(buf[12:])
		buf = buf[24:]
		fmt.Printf("\nsub(%s) super(%s)", in_s.String(), out_s.String());
	}
	fmt.Printf("\n------------------------------------------------------------\n")
	
}
/* UnmarshalMapping */


/*********************************************************************
 *
 *	dealGetMapping:  receives a  request for  the mappings  from a
 *	control application and forwards it to the kernel module using
 *	netlink.
 *
 *********************************************************************/		
func dealGetMapping(c *Conn, m *UserMessage) {
	
	nlmsg, err := NewNetlinkMessage(DYSCO_GET_MAPPING, nil, nil)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	ch, err := netlinkHandler.Query(*nlmsg, 10)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
		return
	}
	fmt.Println("It will go through the channel to print the messages")
	for i := range ch {
		UnmarshalMapping(i.Body)
		//fmt.Println(i)
	}
}
/* dealGetMapping */


/*********************************************************************
 *
 *	dealGetSub:  receives a  request for  the subsession mappings from a
 *	control application and forwards it to the kernel module using
 *	netlink.
 *
 *********************************************************************/
/*
func dealGetSub(c *Conn, m *UserMessage) {
	
	nlmsg, err := NewNetlinkMessage(DYSCO_GET_SUB, nil, nil)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	ch, err := netlinkHandler.Query(*nlmsg, 10)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
		return
	}
	fmt.Println("It will go through the channel to send the messages to the client.")
	for i := range ch {
		UnmarshalMapping(i.Body)
		//fmt.Println(i)
	}
}
*/
/* dealGetSub */


/*********************************************************************
 *
 *	dealGetSuper:  receives a  request for  the session mappings from a
 *	control application and forwards it to the kernel module using
 *	netlink.
 *
 *********************************************************************/
/*
func dealGetSuper(c *Conn, m *UserMessage) {
	
	nlmsg, err := NewNetlinkMessage(DYSCO_GET_SUPER, nil, nil)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	ch, err := netlinkHandler.Query(*nlmsg, 10)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
		return
	}
	fmt.Println("It will go through the channel to send the messages to the client.")
	for i := range ch {
		UnmarshalMapping(i.Body)
		//fmt.Println(i)
	}
}
*/
/* dealGetSuper */


/*********************************************************************
 *
 *	UnmarshalRecTime: shows  the reconfiguration time  of sessions
 *	that  got reconfigured.   It  currently prints  on the  screen
 *	instead  of sending  back  to the  client  that requested  the
 *	mappings, so we need to redirect the output of the daemon to a
 *	file to get the data.
 *
 *********************************************************************/		
func UnmarshalRecTime(body []byte) {
	
	len := binary.BigEndian.Uint16(body[0:])
	// Just the two first bytes are used. Reused code from get mapping.
	
	buf := body[4:]

	if len > 0 {
		fmt.Printf("\n-----------------------Reconfiguration Times-----------------------")
		for i := 0; i < int(len); i++ {
			super    := tcpSessionUnmarshal(buf[0:])
			rec_time := binary.BigEndian.Uint64(buf[12:])
			buf = buf[20:]
			fmt.Printf("\nREC_TIME: %s %d", super.String(), rec_time);
		}
		fmt.Printf("\n-------------------------------------------------------------------\n")
	} else {
		fmt.Println("No reconfiguration FOUND\n");
	}
	
	
}
/* UnmarshalRecTime */


/*********************************************************************
 *
 *	dealGetRecTime:  receives a  request  for the  reconfiguration
 *	times from a control application and forwards it to the kernel
 *	module using netlink.
 *
 *********************************************************************/		
func dealGetRecTime(c *Conn, m *UserMessage) {
	
	nlmsg, err := NewNetlinkMessage(DYSCO_GET_REC_TIME, nil, nil)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	ch, err := netlinkHandler.Query(*nlmsg, 1)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
		return
	}
	fmt.Println("It will go through the channel to print the messages")
	for i := range ch {
		UnmarshalRecTime(i.Body)
		//fmt.Println(i)
	}
}
/* dealGetRecTime */


/*********************************************************************
 *
 *	dealRemPolicy: receives  a request  for policy removal  from a
 *	control application and forwards it to the kernel module using
 *	netlink.
 *
 *********************************************************************/		
func dealRemPolicy() {
	
	nlmsg, err := NewNetlinkMessageNotify(DYSCO_REM_POLICY)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	_, err = netlinkHandler.Query(*nlmsg, 1)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
	}	
}
/* dealRemPolicy */


/*********************************************************************
 *
 *	dealClearAll: receives a request to clear all state inside the
 *	kernel  from a  control  application and  forwards  it to  the
 *	kernel module using netlink.
 *
 *********************************************************************/		
func dealClearAll() {
	
	nlmsg, err := NewNetlinkMessageNotify(DYSCO_CLEAR_ALL)
	if err != nil {
		fmt.Println("could not create Netlink message: %v", err)
		return
	}
	_, err = netlinkHandler.Query(*nlmsg, 1)
	if err != nil {
		fmt.Println("could not write to netlink: %v", err)
	}	
}
/* dealClearAll */


/*********************************************************************
 *
 *	dealCopyState:
 *
 *********************************************************************/		
func dealCopyState(m *UserMessage) {
	
	msg := unMarshalTransferStateMessage(m.body)
	options := Options {
		Src:	msg.super.sip.String(),
		Dst:	msg.super.dip.String(),
		Sport:	int(msg.super.sport),
		Dport:	int(msg.super.dport),
		Proto:	"tcp",
	}

	if Client(msg.dst.String(), DYSCO_MANAGEMENT_PORT, options) {
		fmt.Println("Sending DYSCO_STATE_TRANSFERRED message")
		m.mtype = DYSCO_STATE_TRANSFERRED
		addrLeft := fmt.Sprintf("%s:%d", msg.leftA.String(), DYSCO_SERVER_PORT)
		fmt.Println("address of left anchor", addrLeft)
		leftA, err := NewClient(addrLeft)
		if err != nil {
			fmt.Println("could not create Dysco client for notifying anchors of state")
			return
		}
		addrRight := fmt.Sprintf("%s:%d", msg.rightA.String(), DYSCO_SERVER_PORT)
		fmt.Println("address of right anchor", addrRight)
		rightA, err := NewClient(addrRight)
		if err != nil {
			fmt.Println("could not create Dysco client for notifying anchors of state")
			return
		}
		sc, _ := CreateSCUser(1, []string{"10.0.1.2"})
		nrm := NewReconfigMessage(msg.super, msg.super, msg.super,
			msg.leftA, msg.rightA, 1, msg.src, msg.dst, sc)
		b := nrm.Serializer()
		fmt.Println("body of STATE_TRANSFERRED", b)
		nm := NewUserMessage(DYSCO_STATE_TRANSFERRED, b)
		leftA.Send(nm.Serializer())
		rightA.Send(nm.Serializer())
	} else {
		fmt.Println("iptables client returned false")
	}
}
/* dealCopyState */


/*********************************************************************
 *
 *	dealStateTransferred:   implemented  for   iptables  only   in
 *	dysco_iptables.go.  It is  here  only to  ignore the  messages
 *	DYSCO_STATE_TRANSFERRED.
 *
 *********************************************************************/		
func dealStateTransferred(m *UserMessage) {
}
/* dealStateTransferred */


/*********************************************************************
 *
 *	dealPutState:
 *
 *********************************************************************/		
func dealPutState(m *UserMessage) {
}
/* dealPutState */


/*********************************************************************
 *
 *	handleUserMessage: handles  control messages and  dispath them
 *	to specific handlers.
 *
 *********************************************************************/		
func handleUserMessage(c *Conn) {
	for {
		select {
		case buf := <-c.Recv:
			//c.Log("Received a user message")
			userMsg := UnMarshalUserMessage(buf)
			switch userMsg.mtype {
			case DYSCO_REQUEST_LOCK:
				c.Log("Received user message DYSCO_REQUEST_LOCK from %s",
					userMsg.String())
				dealRLock(c, &userMsg)

			case DYSCO_ACK_LOCK:
				c.Log("Received user message DYSCSO_ACK_LOCK from %s",
					userMsg.String())
				dealAckLock(c, &userMsg)

			case DYSCO_NACK_LOCK:
				c.Log("Received user message DYSCSO_NACK_LOCK from %s",
					userMsg.String())
				dealNAckLock(c, &userMsg)
				
			case DYSCO_SYN:
				c.Log("Received user message DYSCO_SYN from %s",
					userMsg.String())
				dealRsyn(c, &userMsg)
				
			case DYSCO_SYN_ACK:
				c.Log("Received user message DYSCO_SYN_ACK %s",
					userMsg.String())
				dealSynAck(c, &userMsg)
				
			case DYSCO_ACK:
				c.Log("Received user message DYSCO_ACK %s",
					userMsg.String())
				dealAck(c, &userMsg)

			case DYSCO_ACK_ACK:
				c.Log("Received user message DYSCO_ACK_ACK %s",
					userMsg.String())
				//dealAckAck(c, &userMsg)
				
			case DYSCO_FIN:
				c.Log("Received user message: DYSCO_RFIN")

			case DYSCO_POLICY:
				c.Log("Received user message: DYSCO_POLICY")
				dealPolicy(c, &userMsg)
				
			case DYSCO_REM_POLICY:
				c.Log("Received user message: DYSCO_REM_POLICY")
				dealRemPolicy()

			case DYSCO_CLEAR_ALL:
				c.Log("Received user message: DYSCO_CLEAR_ALL")				
				dealClearAll()

			case DYSCO_COPY_STATE:
				c.Log("Received user message: DYSCO_COPY_STATE")
				c.Log("\n%s\n", userMsg.String())
				dealCopyState(&userMsg)

			case DYSCO_PUT_STATE:
				dealPutState(&userMsg)
				
			case DYSCO_STATE_TRANSFERRED:
				c.Log("Received user message: DYSCO_STATE_TRANSFERRED")
				c.Log("\n%s\n", userMsg.String())
				dealStateTransferred(&userMsg)

			case DYSCO_GET_MAPPING:
				c.Log("Received user message: DYSCO_GET_MAPPING")
				c.Log("\n%s\n", userMsg.String())
				dealGetMapping(c, &userMsg)
				
			case DYSCO_GET_REC_TIME:
				c.Log("Received user message: DYSCO_GET_REC_TIME")
				c.Log("\n%s\n", userMsg.String())
				dealGetRecTime(c, &userMsg)
				
			}
		}
	}
}
/* handleUserMessage */
