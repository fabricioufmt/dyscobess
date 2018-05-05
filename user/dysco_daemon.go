/*
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_daemon.go
 * 
 *	Daemon that runs at user space and implements the control protocol.
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
	dysco "./dysco/" 
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"
)


/*********************************************************************
 *
 *	sendReconfigMessage: 
 *
 *********************************************************************/	
func sendReconfigMessage(buf []byte) {
	
	time.Sleep(time.Duration(5) * time.Second)
	fmt.Println("sendReconfigMessage", buf);
	rec, leftAnchor := dysco.NewReconfigMessageRaw(buf)
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_SYN, rec.Serializer())

	addrSrv   := fmt.Sprintf("%s:%d", leftAnchor, dysco.DYSCO_MANAGEMENT_PORT)
	fmt.Println("Server: ", addrSrv)
	fmt.Println(dysco_msg.String())
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
	}
	buf_msg := dysco_msg.Serializer()
	client.Send(buf_msg)	
}


/*********************************************************************
 *
 *	dyscoSplice: 
 *
 *********************************************************************/	
func dyscoSplice() {
	
	fmt.Println("dyscoSplice");
	os.Remove("/tmp/dysco_unix_server")
	conn, err := net.ListenUnixgram("unixgram",
		&net.UnixAddr{"/tmp/dysco_unix_server", "unixgram"})
	
	if err != nil {
		panic(err)
	}   
	defer os.Remove("/tmp/dysco_unix_server")

	//gid, err := user.LookupGroup("nogroup")
	uid, err := user.Lookup("nobody")
	uid_n, err := strconv.Atoi(uid.Uid)
	gid_n, err := strconv.Atoi(uid.Gid)
	os.Chown("/tmp/dysco_unix_server", uid_n, gid_n)
	for {
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			panic(err)
		}
		
		go sendReconfigMessage(buf[:n])
	}   
	
}


/*********************************************************************
 *
 *	main: 
 *
 *********************************************************************/	
func main() {
	srvPort := dysco.DYSCO_SERVER_PORT
	var timeout time.Duration

	timeout = time.Duration(100)
	if len(os.Args) > 3 {
		fmt.Printf("Usage: %s [timeout] [port]\n", os.Args[0])
		os.Exit(1)
	} else if len(os.Args) == 2 {
		to, err := strconv.Atoi(os.Args[1])
		if err != nil {
			fmt.Println("could not convert timeout", err)
			os.Exit(1)
		}
		timeout = time.Duration(to)
	} else if len(os.Args) == 3 {
		sp, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Println("could not get port", err)
			os.Exit(1)
		}
		srvPort = sp
	}
	
	addr := fmt.Sprintf("0.0.0.0:%d", srvPort)
	serverUDP, err := dysco.NewUDPServer(addr)
	if err != nil {
		log.Fatal("Could not create Dysco server")
		os.Exit(1)
	}
	defer serverUDP.Close()

	
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println("Could not get interface addresses")
		os.Exit(1)
	}
	var listenAddrs []string
	listenAddrs = make([]string, len(ifaces))
	for i, v := range ifaces {
		var str string
		
		tmp := []byte(v.String())
		for i := 0; i < len(tmp); i++ {
			if tmp[i] == '/' {
				str = string(tmp[0:i])
			}
		}
		listenAddrs[i] = str
	}
	serverUDP.SetInterfaces(listenAddrs)
	serverUDP.SetTimeOut(timeout)
	serverUDP.OpenNetlink()

	//go dyscoSplice()
	
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGINT)
	go func() {
		_ = <- sigs
		//fmt.Println("Dysco: received Control C", sig)
		os.Exit(0)
	}()
	
	addr = fmt.Sprintf("0.0.0.0:%d", dysco.DYSCO_MANAGEMENT_PORT)
	policy, err := dysco.NewUDPServer(addr)
	policy.SetInterfaces(listenAddrs)
	policy.SetTimeOut(timeout)

	serverTCP, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("Error creating TCP server", err)
		os.Exit(1)		
	}
	go func() {
		for {
			sock, err := serverTCP.Accept()
			if err != nil {
				fmt.Println("error in TCP accept", err)
			} else {
				go dysco.IpTablesServer(sock)
			}
		}
	}()
	
	for {
		time.Sleep(time.Second * 60)
		//log.Print("\nDysco_daemon still running")
	}
}
