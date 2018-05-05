/*
 *
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_client.go
 *
 *	This file was renamed from
 *	github.com/reusee/reliable-udp/client.go.
 *
 *	There are  only a  few changes from  the original  file. Also,
 *	some comments were added to  make the file consistent with the
 *	other code of the project.
 *
 *	Part of this code was borrowed from github.com/reusee.
 *	The following packages are required:
 *	- github.com/vishvananda/go-netlink (Netlink library)
 *	- github.com/reusee/closer
 *	- github.com/reusee/inf-chan
 *
 */
/* */

package dysco

import (
	"log"
	"net"
)

/*********************************************************************
 *
 *	NewClient:
 *
 *********************************************************************/	
func NewClient(addrStr string) (*Conn, error) {
	addr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}
	
	udpConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	
	conn := makeConn("Client", udpConn)
	conn.writeUDP = func(data []byte) error {
		_, err := udpConn.Write(data)
		return err
	}

	udpConnClosed := false
	conn.OnClose(func() {
		udpConnClosed = true
		udpConn.Close()
	})

	go handleUserMessage(conn)
	
	go func() {
		for {
			packetData := make([]byte, 1500)
			n, _, err := udpConn.ReadFromUDP(packetData)
			if err != nil {
				if udpConnClosed {
					return
				} else {
					log.Fatalf("client read error %v", err)
				}
			}
			packetData = packetData[:n]
			conn.incomingPacketsIn <- packetData
		}
	}()
	
	// Have to check if I can start here. Have to send a packet because the
	// receiver expects an answer.
	go conn.start() // start receiver thread handler (handles timeout too)	
	return conn, nil
}
/* NewClient */
