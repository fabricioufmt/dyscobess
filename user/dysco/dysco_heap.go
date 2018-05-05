/*
 *	Dynamic Service Chaining with Dysco
 *	Dysco user agent: dysco_heap.go
 *	Auxiliary routines for Heap management.
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

type Heap []*Packet

func (q Heap) Len() int {return len(q)}

func (q Heap) Less(i, j int) bool {return q[i].serial < q[j].serial}

func (q Heap) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

func (q *Heap) Push(v interface{}) {
	n := len(*q)
	item := v.(*Packet)
	item.index = n
	*q = append(*q,item)
}

func (q *Heap) Pop() interface{} {
	old := *q
	n := len(old)
	item := old[n-1]
	item.index = -1
	*q = old[0:n-1]
	return item
}

func (q *Heap) Peek() *Packet {
	return (*q)[len(*q)-1]
}
