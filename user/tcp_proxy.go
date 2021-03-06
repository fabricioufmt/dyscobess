/*
 * 
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: tcp_proxy.go
 *
 *	Implements  a TCP  proxy that  is instrummented  to trigger  a
 *	reconfiguration at a time specified at the command line.
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
 */

package main

import (
	dysco "./dysco"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const EXIT_FAILURE = 1
const MAX_BUFFER   = 4000

var spliceTime	int
var lhop 	int
var rhop 	int

var n           int
var buff[]      byte


/*********************************************************************
 *
 *	spliceConnections: builds  a control message and  sends to the
 *	Dysco daemon  on the left anchor  of the proxy to  trigger the
 *	proxy removal.
 *
 *********************************************************************/	
func spliceConnections(l, r net.Conn) {

     	super := dysco.NewTcpSession(net.ParseIP("0"), net.ParseIP("0"), 0, 0)

     	c1Local  := strings.Split(l.LocalAddr().String(), ":")
	c1Remote := strings.Split(l.RemoteAddr().String(), ":")
	
	c2Local  := strings.Split(r.LocalAddr().String(), ":")
	c2Remote := strings.Split(r.RemoteAddr().String(), ":")

	srcPort, _ := strconv.Atoi(c1Remote[1])
	dstPort, _ := strconv.Atoi(c1Local[1])

	leftSS := dysco.NewTcpSession(net.ParseIP(c1Remote[0]),
		  net.ParseIP(c1Local[0]), uint16(srcPort), uint16(dstPort))

	fmt.Printf(" leftSS: %s:%d -> %s:%d\n", c1Remote[0], srcPort, c1Local[0], dstPort)
	L_SS := c1Remote[0] + " " + c1Remote[1] + " " + c1Local[0] + " " + c1Local[1]

	srcPort, _ = strconv.Atoi(c2Local[1])
	dstPort, _ = strconv.Atoi(c2Remote[1])
	
	rightSS := dysco.NewTcpSession(net.ParseIP(c2Local[0]),
	  	   net.ParseIP(c2Remote[0]), uint16(srcPort), uint16(dstPort))

        fmt.Printf("rightSS: %s:%d -> %s:%d\n\n", c2Local[0], srcPort, c2Remote[0], dstPort)
	R_SS := c2Local[0] + " " + c2Local[1] + " " + c2Remote[0] + " " + c2Remote[1]

	if lhop == 0 && rhop == 0 {
		//Starting out-of-band reconfiguration
	
		/*
		conn, err := net.Dial("tcp", "172.16.0.1:6999")
		if err != nil {
			fmt.Println("could not open server connection")
			return
		}
		
		conn.Write(leftSS.Serializer())
		conn.Write(rightSS.Serializer())

		conn.Close()
		*/
		/*	   
		chain := []string{c1Remote[0], c2Remote[0]}
		sc, _ := dysco.CreateSCUser(2, chain)
		*/
		/*
		var sc          *dysco.ServiceChain
		var stateTransf uint16
		
		if middlebox == "" {
			chain := []string{c2Remote[0]}
			chain := []string{"10.0.4.2"}
			sc, _ = dysco.CreateSC(1, chain)
			stateTransf = dysco.NOSTATE_TRANSFER
		} else {
			//chain := []string{middlebox, c2Remote[0]}
			chain := []string{middlebox, "10.0.4.2"}
			sc, _ = dysco.CreateSC(2, chain)
			stateTransf = dysco.NOSTATE_TRANSFER
		}

		dysco_msg :=  dysco.NewReconfigMessage(super, leftSS, rightSS,		
			net.ParseIP(c1Remote[0]), net.ParseIP(c2Remote[0]),
			stateTransf, net.ParseIP("0.0.0.0"),
			net.ParseIP("0.0.0.0"), sc)
			
		time.Sleep(time.Duration(spliceTime) * time.Second)	

		//addrSrv := fmt.Sprintf("%s:%d", c1Remote[0], dysco.DYSCO_MANAGEMENT_PORT)
		addrSrv := fmt.Sprintf("172.16.0.1:%d", dysco.DYSCO_MANAGEMENT_PORT)
		fmt.Printf("Trying to connect %s... ", addrSrv)

		conn, err = net.Dial("tcp", addrSrv)
		if err != nil {
			fmt.Println("could not connect Dysco daemon.")
			return
		}
		fmt.Println("Ok.")
		
		buf := dysco_msg.Serializer()
		n, _ := conn.Write(buf)
		fmt.Printf("Sent %d bytes\n", n)
		conn.Close()
		*/	
	} else {
		//Starting in-band reconfiguration

		// ./locking <L_si> <L_sp> <L_di> <L_dp> <R_si> <R_sp> <R_di> <R_dp> <lhop> <rhop>
		_, _ = exec.Command("./locking", L_SS, R_SS, lhop, rhop).CombinedOutput()
	}
}


/*********************************************************************
 *
 *	pipe: forwards data from one socket to the other.
 *
 *********************************************************************/	
func pipe(a, b net.Conn) error {
	errors := make(chan error, 1)

	copy := func(write, read net.Conn) {
		_, err := io.Copy(write, read)
		errors <- err
	}
	go copy(a, b)
	go copy(b, a)
	return <- errors
}
/* pipe */


/*********************************************************************
 *
 *	handleRequest: handles a new connection request.
 *
 *********************************************************************/	
func handleRequest(w net.Conn, serverAddr string) {
	defer w.Close()

	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		fmt.Println("could not open server connection")
		return
	}
	defer conn.Close()

	go spliceConnections(w, conn)

	pipe(w, conn)
}
/* handleRequest */


/*********************************************************************
 *
 *	usage: shows the program usage.
 *
 *********************************************************************/	
func usage() {
	fmt.Println("Usage: tcp_proxy <port-number> <server-addr> <server-port> <splice-time> [lhop] [rhop]")
	os.Exit(EXIT_FAILURE)
}
/* usage */


/*********************************************************************
 *
 *	usageError: shows error message and the program usage.
 *
 *********************************************************************/	
func usagePortError() {
	fmt.Print("Port number must be a positive number! ")
	usage()
}
/* usageError */


/*********************************************************************
 *
 *	usageError: shows error message and the program usage.
 *
 *********************************************************************/	
func usageError() {
	fmt.Print("Port number must be a positive number! ")
	usage()
}
/* usageError */


/*********************************************************************
 *
 *	main: main function.
 *
 *********************************************************************/	
func main() {
	var str []string
	var serverStr []string
	
	if len(os.Args) < 5 || len(os.Args) > 7 {
		usage()
	}
	
	port, err := strconv.Atoi(os.Args[1])
	if err != nil || port < 0 {
		usagePortError()
	}

	str = append(str, ":", os.Args[1])
	portStr := strings.Join(str, "")	
	ln, err := net.Listen("tcp4", portStr)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
	
	serverPort, err := strconv.Atoi(os.Args[3])
	if err != nil || serverPort < 0 {
		usageError()
	}
	
	serverStr   = append(serverStr, os.Args[2], ":", os.Args[3])
	serverAddr := strings.Join(serverStr, "")
	
	spliceTime, err = strconv.Atoi(os.Args[4])
	if err != nil || spliceTime < 0 {
		usageError()
	}

	lhop = 0
	rhop = 0
	if len(os.Args) == 7 {
		lhop = strconv.Atoi(os.Args[5])
		rhop = strconv.Atoi(os.Args[6])
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal("Accept: ", err)
		}
		
		go handleRequest(conn, serverAddr)
	}
}
/* main */
