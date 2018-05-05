/*
 *
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_conn.go
 *
 *	This module handles UDP connections.
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
 *	Part of this code was borrowed from github.com/reusee.
 *	The following packages are required:
 *	- github.com/vishvananda/go-netlink (Netlink library)
 *	- github.com/reusee/closer
 *	- github.com/reusee/inf-chan
 *
 */
package dysco

import (
	"bytes"
	"container/heap"
	"container/list"
	"encoding/binary"
	"fmt"
	"math/rand"
	//"log"
	"net"
	"time"
	"github.com/reusee/closer"
	ic "github.com/reusee/inf-chan"
	"sync"
)

const DYSCO_TIMEOUT = 1000
const DYSCO_RETRIES = 10

var dysco_timeout = time.Duration(DYSCO_TIMEOUT)

var (
	ackTimerTimeout = time.Millisecond * DYSCO_TIMEOUT
)

type Conn struct {
	closer.Closer
	*Logger

	sideConn		string	// for debugging: identifies client or server
	writeUDP		func([]byte) error
	serial			uint32
	ackRecv			uint32
	ackSerial		uint32

	incomingPacketsIn	chan []byte
	incomingPackets		chan []byte
	recvIn			chan []byte
	Recv			chan []byte

	unackPackets		*list.List
	unackMutex		sync.Mutex
	
	packetHeap		*Heap
	heapMutex		sync.Mutex
	
	ackCheckTimer		*Timer
	ackTimer		*time.Timer

	retransmitTimer		*time.Timer
	
	StatResend		uint32
	udpConn			*net.UDPConn
}


/*********************************************************************
 *
 *	makeConn:
 *
 *********************************************************************/	
func makeConn(side string, udpSocket *net.UDPConn) *Conn {
	conn := &Conn {
		sideConn:		side,
		serial:			uint32(rand.Intn(65536)),
		Logger:			newLogger(),
		incomingPacketsIn:	make(chan []byte, 10),
		incomingPackets:	make(chan []byte, 10),
		recvIn:			make(chan []byte, 10),
		Recv:			make(chan []byte, 10),
		unackPackets:		list.New(),
		packetHeap:		new(Heap),
		ackCheckTimer:		NewTimer(time.Millisecond * dysco_timeout),
		ackTimer:		time.NewTimer(ackTimerTimeout),
		udpConn:		udpSocket,
	}
	heap.Init(conn.packetHeap)
	ic.Link(conn.incomingPacketsIn, conn.incomingPackets)
	ic.Link(conn.recvIn, conn.Recv)
	conn.OnClose(func() {
		conn.Logger.Close()
		close(conn.incomingPacketsIn)
		close(conn.recvIn)
		conn.ackCheckTimer.Close()
	})
	return conn
}
/* makeConn */


/*********************************************************************
 *
 *	Conn.sendPacket:
 *
 *********************************************************************/	
func (c *Conn) sendPacket(packet Packet) error {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, packet.serial)
	binary.Write(buf, binary.LittleEndian, c.ackSerial)
	buf.WriteByte(packet.flag)
	buf.Write(packet.data)
	return c.writeUDP(buf.Bytes());
}
/* Conn.sendPacket */


/*********************************************************************
 *
 *	Conn.Send:
 *
 *********************************************************************/	
func (c *Conn) Send(data []byte) error {
	packet := c.newPacket(data, ACK|SYNC)
	err := c.sendPacket(packet)
	if err != nil {
		fmt.Println("Error sending packet", err)
		return err
	}
	
	// push to unackPackets
	packet.sentTime = c.ackCheckTimer.Now

	
	c.unackMutex.Lock()
	c.unackPackets.PushBack(&packet)
	c.unackMutex.Unlock()
	
	// reset ackTimer
	if !c.ackCheckTimer.Ticking() {
		c.ackCheckTimer.ResumeTicking(ackTimerTimeout)
	}
	
	return nil
}
/* Conn.Send */


/*********************************************************************
 *
 *	Conn.checkRetransmission:
 *
 *********************************************************************/	
func (c *Conn) checkRetransmission() {
	c.unackMutex.Lock()
	defer c.unackMutex.Unlock()

	//c.Log("%s: checkRetransmission", c.sideConn)
	if c.unackPackets.Len() < 1 {
		//c.Log("%s: stop ticking", c.sideConn)
		c.ackCheckTimer.StopTicking()
		return
	}
	now := c.ackCheckTimer.Now
	for e := c.unackPackets.Front(); e != nil; e = e.Next() { // TODO selective check
		packet := e.Value.(*Packet)
		if now > packet.sentTime && now-packet.sentTime > packet.resendTimeout {
			c.Log("%s: timeout serial %d now %d sent %d timeout %d",
				c.sideConn, packet.serial, now, packet.sentTime,
				packet.resendTimeout)
			if c.StatResend > DYSCO_RETRIES {
				c.Log("%s: giving up on sending packet serial %d after %d tries",
					c.sideConn, packet.serial, c.StatResend)
				c.unackPackets.Remove(e)
			} else {
				c.sendPacket(*packet) // resend
				packet.sentTime = now // reset sent time
				c.StatResend++
				c.Log("%s: resend %d at %d nextCheck %d", c.sideConn,
					packet.serial, now, packet.resendTimeout)
			}
		}
	}
}
/* Conn.checkRetransmission */


/*********************************************************************
 *
 *	Conn.sendAck:
 *
 *********************************************************************/	
func (c *Conn) sendAck() {
	if c.serial > c.ackRecv {
		packet := c.newPacket([]byte{}, ACK)
		c.sendPacket(packet)
		c.ackTimer.Reset(ackTimerTimeout)
		c.Log("%s: send Ack", c.sideConn)
	} else {
		c.Log("%s: sendAck called, but ackSerial == serial", c.sideConn)
	}
}
/* Conn.sendAck */


/*********************************************************************
 *
 *	readPacket:
 *
 *********************************************************************/	
func (c *Conn) readPacket(packetData []byte) (uint32, uint32, byte, []byte) {
	serial, ackSerial, flag, data := readPacket(packetData)
	return serial, ackSerial, flag, data
}
/* Conn.readPacket */


/*********************************************************************
 *
 *	Conn.handlePacket:
 *
 *********************************************************************/	
func (c *Conn) handlePacket(packetData []byte) {
	serial, ackSerial, flags, data := c.readPacket(packetData)

	if len(data) > 0 {
		if (flags & SYNC) != 0 {
			if c.ackSerial == 0 {
				c.ackSerial = serial
			}
		} else {
			c.Log("%s: flags & SYNC == 0", c.sideConn);
		}
		
		if serial == c.ackSerial { // in order
			c.recvIn <- data
			c.ackSerial++
			packet := c.newPacket([]byte{}, SYNC|ACK)
			err := c.sendPacket(packet)
			if err != nil {
				c.Log("%s: error sending ack %v", c.sideConn, err)
			}
			
		} else if serial < c.ackSerial { // duplicated packet. ack got lost?
			c.recvIn <- data
			packet := c.newPacket([]byte{}, SYNC|ACK)
			err := c.sendPacket(packet)
			if err != nil {
				c.Log("%s: error sending ack %v", c.sideConn, err)
			}
			
		} else if serial > c.ackSerial { // out of order
			//log.Fatal("packet out of order. It should never happen.")

			c.heapMutex.Lock()
			heap.Push(c.packetHeap, &Packet{
				serial:	serial,
				data:	data,
			})
			c.Log("%s: out of order packet %d heapLen %d",
				c.sideConn, serial, c.packetHeap.Len())
			for c.packetHeap.Len() > 0 {
				packet := c.packetHeap.Peek()
				if packet.serial == c.ackSerial {
					heap.Pop(c.packetHeap)
					if len(packet.data) > 0 {
						c.recvIn <- packet.data
						c.Log("%s: provide serial %d length %d",
							c.sideConn, serial, len(data))
					}
					c.ackSerial++
				} else if packet.serial < c.ackSerial { //duplicated
					heap.Pop(c.packetHeap)
				} else {
					break
				}
			}
			c.heapMutex.Unlock()			
		}
	} 

	c.unackMutex.Lock()
	for e := c.unackPackets.Front(); e != nil; e = e.Next() {
		packet := e.Value.(*Packet)
		if packet.serial >= ackSerial {
			break
		}
//		c.Log("%s: acked %d in now=%d sentTime=%d",
//			c.sideConn,
//			packet.serial,
//			c.ackCheckTimer.Now,
//			packet.sentTime)
		c.unackPackets.Remove(e)
	}	
	c.unackMutex.Unlock()
	
	// TODO process flags
	_ = flags
}
/* Conn.handlePacket */


/*********************************************************************
 *
 *	Conn.start:
 *
 *********************************************************************/	
func (c *Conn) start() {
	for {
		select {
		case packetData, ok := <-c.incomingPackets:
			if !ok {return} // conn closed
			c.handlePacket(packetData)
			
		case <-c.ackCheckTimer.Tick:
			c.checkRetransmission()
		}
	}
}
/* Conn.Start */

