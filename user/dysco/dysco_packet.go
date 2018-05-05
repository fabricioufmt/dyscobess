/*
*
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_packet.go
 *
 *	This module creates and reads packets in different formats.
 *
 *	Authors: Ronaldo A. Ferreira (raf@facom.ufms.br)
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
 */

package dysco

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
)

const (
	SYNC  = byte(1)
	FIN   = byte(2)
	ACK   = byte(4)
	RSYN  = byte(8)
	RACK  = byte(16)
)

type Packet struct {
	serial		uint32
	flag		byte
	index		int	// for heap
	sentTime	uint	// for congestion
	resendTimeout	uint	// retransmit timeout
	data		[]byte
}


/*********************************************************************
 *
 *	Conn.newPacket:
 *
 *********************************************************************/	
func (c *Conn) newPacket(data []byte, flags ...byte) Packet {
	var flag byte
	
	for _, f := range flags {
		flag |= f
	}
	
	packet := Packet {
		serial:		c.serial,
		flag:		flag,
		resendTimeout:	1,	// one second?
		data:		data,
	}
	
	if len(data) > 0 {
		c.serial++
	}
	
	return packet
}
/* Conn.newPacket */


/*********************************************************************
 *
 *	readPacket:
 *
 *********************************************************************/	
func readPacket(packetData []byte) (uint32, uint32, byte, []byte) {
	
	reader := bytes.NewReader(packetData)
	var serial, ackSerial uint32
		
	binary.Read(reader, binary.LittleEndian, &serial)
	binary.Read(reader, binary.LittleEndian, &ackSerial)
	flag, _ := reader.ReadByte()
	data, _ := ioutil.ReadAll(reader)
		
	return serial, ackSerial, flag, data
}
/* readPacket */
