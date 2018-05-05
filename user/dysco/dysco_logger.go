/*
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_logger.go
 *	Module for logging messages.
 *
 *	Authors:
 *	// Removed while under submission
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *	WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 *	OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *	IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *	INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *	OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *	HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *	STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *	IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *	POSSIBILITY OF SUCH DAMAGE.
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
	"fmt"
	"github.com/reusee/closer"
	ic "github.com/reusee/inf-chan"
)

type Logger struct {
	closer.Closer
	logsIn		chan string
	Logs		chan string
}

func newLogger() *Logger {
	logger := &Logger {
		logsIn:	make(chan string),
		Logs:	make(chan string),
	}
	ic.Link(logger.logsIn, logger.Logs)
	logger.OnClose(func() {
		close(logger.logsIn)
	})
	return logger
}

func (l *Logger) Log(format string, args ...interface{}) {
//	l.logsIn <- fmt.Sprintf(format, args...)
	fmt.Println(fmt.Sprintf(format, args...))
}
