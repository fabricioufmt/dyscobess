/*
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_timer.go
 *	Timer management of the control protocol.
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
	"time"
	"github.com/reusee/closer"
)

type Timer struct {
	closer.Closer
	Now		uint
	Tick		chan struct{}
	ticking		bool
	ticker		*time.Timer
}

func (t *Timer) StopTicking() {
	t.ticking = false
}

func (t *Timer) ResumeTicking(interval time.Duration) {
	t.ticking = true
	t.ticker.Reset(interval)
}

func (t *Timer) Ticking() (bool) {
	return t.ticking
}

func NewTimer(interval time.Duration) *Timer {
	timer := &Timer{
		Tick:		make(chan struct{}),
		ticking:	true,
		ticker:		time.NewTimer(interval),
	}
	
	stop   := make(chan bool)
	
	go func() {
		for {
			select {
			case <- stop:
				return
			case <- timer.ticker.C:
				timer.Now++
				timer.Tick <- struct{}{}
				if timer.ticking {timer.ticker.Reset(interval)}
			}
		}
	}()
	
	timer.OnClose(func() {
		close(stop)
	})
	return timer
}
