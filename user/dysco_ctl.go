/*
 * 
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_ctl.go
 *
 *	Command line interface to send commands to the Dysco agents.
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
	"bytes"
	"bufio"
	"fmt"
	dysco "./dysco/"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	POLICY = 1+iota
	REMOVE_POLICY
	RECONFIG
	CLEAR
	CLEAR_ALL
	COPY_STATE
	REC_W_STATE
	GET_MAPPING
	GET_SUB
	GET_SUPER
	GET_REC_TIME
	HELP
	CONSOLE
	EXIT
)


/* Available commands in the controller */	
var cmdMap = map[string]uint16 {
	"policy":	POLICY,
	"rempol":	REMOVE_POLICY,
	"rec":		RECONFIG,
	"clear":	CLEAR,
	"clearall":	CLEAR_ALL,
	"copy":		COPY_STATE,
	"rec_state":	REC_W_STATE,
	"get_mapping":	GET_MAPPING,
	"get_sub":	GET_SUB,
	"get_super":	GET_SUPER,
	"get_rec_time":	GET_REC_TIME,
	"help":		HELP,
	"console":	CONSOLE,
	"exit":		EXIT,
}


/* Help with the available commands. */	
var cmdHelp = map[int]string {
	POLICY:		"policy <host> <sc_len> <chain> <filter>",
	REMOVE_POLICY:	"rempol <host>",
	RECONFIG:	"rec <leftA> <newMB> <rightA> <sport> <dport>",
	CLEAR:		"clear <host> <leftA> <rightA> <supersession>",
	CLEAR_ALL:	"clearall <host>",
	COPY_STATE:	"copy  <src> <dst> <leftA> <rightA> <sport> <dport>",
	REC_W_STATE:	"rec_state <leftA> <newMB> <rightA> <sport> <dport> <oldMB>",
	GET_MAPPING:	"get_mapping <host>",
	GET_SUB:	"get_sub <host>",
	GET_SUPER:	"get_super <host>",
	GET_REC_TIME:	"get_rec_time <host>",
	HELP:		"help",
	CONSOLE:	"console",
	EXIT:		"exit",
}

var rec_semantic = uint32(0)

	
/*********************************************************************
 *
 *	addPocily: sends a message to the Dysco daemon to add a policy
 *	in the kernel agent.
 *
 *********************************************************************/	
func addPolicy(s []string) {
	if len(s) < 4 {
		helpCmdLine(POLICY)
		return
	}
	sc_len, err := strconv.Atoi(s[1])
	if err != nil {
		fmt.Println("invalid sc_len", s[1])
		helpCmdLine(POLICY)
		return
	}
	sc, err := dysco.CreateSC(sc_len, s[2:])
	if err != nil {
		fmt.Println("invalid sc", strings.Join(s[2:sc_len+2], " "))
		helpCmdLine(POLICY)
		return
	}
	filter := strings.Join(s[sc_len+2:], " ")
	bpf, err := dysco.CreateFilter(filter)
	if err != nil {
		fmt.Println("invalid filter", filter)
		helpCmdLine(POLICY)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	//fmt.Println(addrSrv)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	body := bytes.Join([][]byte{sc.Serializer(), bpf.Serializer()}, []byte{})
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_POLICY, body)
	client.Send(dysco_msg.Serializer())
}
/* addPolicy */

	
/*********************************************************************
 *
 *	remPolicy:  send a  message to  the Dysco  daemon to  remove a
 *	policy stored in the kernel agent.
 *
 *********************************************************************/	
func remPolicy(s []string) {
	if len(s) != 1 {
		helpCmdLine(REMOVE_POLICY)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_REM_POLICY, []byte{})
	client.Send(dysco_msg.Serializer())
}
/* remPolicy */


/*********************************************************************
 *
 *	triggerReconfig:  triggers  a  reconfiguration that  does  not
 *	involve state transfer.
 *
 *********************************************************************/	
func triggerReconfig(s []string) {
	if len(s) != 5 {
		helpCmdLine(RECONFIG)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	src_port, err1 := strconv.Atoi(s[3])
	dst_port, err2 := strconv.Atoi(s[4])
	if err1 != nil || err2 != nil {
		fmt.Println("could not convert port numbers")
		return
	}
	tcps := dysco.NewTcpSession(net.ParseIP(s[0]), net.ParseIP(s[2]),
		uint16(src_port), uint16(dst_port))
	sc, err := dysco.CreateSCUser(3, s[0:])
	if err != nil {
		fmt.Println("could not create service chain")
		return
	}
	rec := dysco.NewReconfigMessage(tcps, tcps, tcps, net.ParseIP(s[0]),
		net.ParseIP(s[2]), 0, net.ParseIP(s[0]), net.ParseIP(s[0]), sc)
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_SYN, rec.Serializer())
	fmt.Println(dysco_msg.String())

	buf := dysco_msg.Serializer()
	client.Send(buf)
}
/* triggerReconfig */


/*********************************************************************
 *
 *	recWithState: triggers a reconfiguration with state transfer.
 *
 *********************************************************************/	
func recWithState(s []string) {
	if len(s) != 6 {
		helpCmdLine(REC_W_STATE)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	src_port, err1 := strconv.Atoi(s[3])
	dst_port, err2 := strconv.Atoi(s[4])
	if err1 != nil || err2 != nil {
		fmt.Println("could not convert port numbers")
		return
	}
	tcps := dysco.NewTcpSession(net.ParseIP(s[0]), net.ParseIP(s[2]),
		uint16(src_port), uint16(dst_port))
	sc, err := dysco.CreateSCUser(3, s[0:])
	if err != nil {
		fmt.Println("could not create service chain")
		return
	}
	rec := dysco.NewReconfigMessage(tcps, tcps, tcps, net.ParseIP(s[0]),
		net.ParseIP(s[2]), 1, net.ParseIP(s[5]), net.ParseIP(s[1]), sc)
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_SYN, rec.Serializer())
	fmt.Println(dysco_msg.String())

	buf := dysco_msg.Serializer()
	client.Send(buf)
}
/* recWithState */


/*********************************************************************
 *
 *	clearState:
 *
 *********************************************************************/	
func clearState(s []string) {
	helpCmdLine(CLEAR)
}
/* clearState */


/*********************************************************************
 *
 *	clearAllState: sends  a message to  the Dysco daemon  to clear
 *	all state currently stored in the kernel.
 *
 *********************************************************************/	
func clearAllState(s []string) {
	if len(s) != 1 {
		helpCmdLine(CLEAR_ALL)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_CLEAR_ALL, []byte{})
	client.Send(dysco_msg.Serializer())
}
/* clearAllState */


/*********************************************************************
 *
 *	copyState:
 *
 *********************************************************************/	
func copyState(s []string) {
	fmt.Println("Running copyState")
	if len(s) != 6 {
		helpCmdLine(COPY_STATE)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	
	src_port, err1 := strconv.Atoi(s[4])
	dst_port, err2 := strconv.Atoi(s[5])
	if err1 != nil || err2 != nil {
		fmt.Println("could not convert port numbers")
		return
	}
	super := dysco.NewTcpSession(net.ParseIP(s[2]), net.ParseIP(s[3]),
		uint16(src_port), uint16(dst_port))
	
	copy_msg := dysco.NewTransferStateMessage(super, net.ParseIP(s[0]), net.ParseIP(s[1]),
		net.ParseIP(s[2]), net.ParseIP(s[3]))
	
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_COPY_STATE, copy_msg.Serializer())
	fmt.Println(dysco_msg.String())
	
	buf := dysco_msg.Serializer()
	client.Send(buf)
}
/* copyState */


/*********************************************************************
 *
 *	helpCmdLine: prints the available commands (help).
 *
 *********************************************************************/	
func helpCmdLine(cmd int) {
	if cmd == HELP {
		fmt.Printf("\nAvaliable commands:\n")
		for _, v := range cmdHelp {
			fmt.Printf("\t%s\n", v)
		}
	} else {
		fmt.Printf("\nInvalid command")
		fmt.Printf("\nUsage: %s\n", cmdHelp[cmd])
	}
}
/* helpCmdLine */


/*********************************************************************
 *
 *	helpHelper: calls  a function to print  the available commands
 *	(help).
 *
 *********************************************************************/	
func helpHelper(s []string) {
	helpCmdLine(HELP)
}
/* helpHelper */


/*********************************************************************
 *
 *	exitHelper: exits the controller.
 *
 *********************************************************************/	
func exitHelper(s []string) {
	os.Exit(1)
}
/* exitHelper */


/*********************************************************************
 *
 *	getMapping:  this  function sends  the  command  to the  Dysco
 *	daemon  to   get  the   current  mappings  installed   in  the
 *	kernel.  The  mappings show  how  a  session  is mapped  to  a
 *	subsession and vice-versa.
 *
 *********************************************************************/	
func getMapping(s []string) {
	if len(s) != 1 {
		helpCmdLine(GET_MAPPING)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_GET_MAPPING, []byte{})
	client.Send(dysco_msg.Serializer())
}
/* getMapping */


/*********************************************************************
 *
 *	getRecTime:  this functions  sends  the command  to the  Dysco
 *	daemon to get the reconfiguration times.
 *
 *********************************************************************/	
func getRecTime(s []string) {
	if len(s) != 1 {
		helpCmdLine(GET_REC_TIME)
		return
	}
	addrSrv := fmt.Sprintf("%s:%d", s[0], dysco.DYSCO_SERVER_PORT)
	client, err := dysco.NewClient(addrSrv)
	if err != nil {
		fmt.Println("could not create Dysco client")
		return
	}
	dysco_msg := dysco.NewUserMessage(dysco.DYSCO_GET_REC_TIME, []byte{})
	client.Send(dysco_msg.Serializer())
}
/* getRecTime */


type cmdFunc func([]string)

// Vector with the  function pointers to the  functions that implement
// the controller commands.
var functionMap = map[uint16]cmdFunc {
	POLICY:		addPolicy,
	REMOVE_POLICY:	remPolicy,
	RECONFIG:	triggerReconfig,
	CLEAR:		clearState,
	CLEAR_ALL:	clearAllState,
	COPY_STATE:	copyState,
	REC_W_STATE:	recWithState,
	GET_MAPPING:	getMapping,
	GET_REC_TIME:	getRecTime,
	HELP:		helpHelper,
	EXIT:		exitHelper,
}


/*********************************************************************
 *
 *	cmdLine: "parses" the command line and calls the function that
 *	implements the given command.
 *
 *********************************************************************/		
func cmdLine(s []string) {
	cmd, ok := cmdMap[s[0]]
	if !ok || cmd < POLICY || cmd > EXIT {
		fmt.Printf("\nInvalid command\n")
		helpCmdLine(HELP)
	} else {
		if cmd == CONSOLE {return}
		
		f, _ := functionMap[cmd]
		f(s[1:])
	}
	return
}
/* cmdLine */


/*********************************************************************
 *
 *	interactive:
 *
 *********************************************************************/	
func interactive() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Dysco command $ ")
		cmd, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {os.Exit(1)}
		}
		cmdFmt := cmd[:len(cmd)-1]
		var cmdLineStr []string
		if len(cmdFmt) > 0 {
			inputLine := strings.Split(cmdFmt, " ")
			for i, v := range inputLine {
				inputLine[i] = strings.TrimSpace(v)
				if inputLine[i] != "" {
					cmdLineStr = append(cmdLineStr, inputLine[i])
				}
				
			}
			cmdLine(cmdLineStr)
		}
	}	
}
/* interactive */


/*********************************************************************
 *
 *	main: 
 *
 *********************************************************************/	
func main() {
	if len(os.Args) < 2 {
		helpCmdLine(HELP)
		os.Exit(0);
	}
	cmd, ok := cmdMap[os.Args[1]]
	if !ok || cmd < POLICY || cmd > EXIT {
		fmt.Printf("\nInvalid command\n")
		helpCmdLine(HELP)
		os.Exit(0)
	}
	if cmd == CONSOLE {
		interactive()
	} else {
		cmdLine(os.Args[1:])
	}
	
}
/* main */
