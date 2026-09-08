package p2p

import (
	"net"
	"sync"
	"time"
)

// ioTimeout bounds how long a single read or write on a peer connection may
// take. Without a deadline, a slow or malicious peer that never finishes
// sending/receiving a frame would tie up a goroutine and its connection
// indefinitely (a simple resource-exhaustion / slow-loris style DoS).
const ioTimeout = 15 * time.Second

// Peer wraps one TCP connection to another node. writeMu serializes writes
// since multiple goroutines (gossip fan-out, direct replies) may write to
// the same peer concurrently.
type Peer struct {
	conn       net.Conn
	remoteAddr string // the peer's advertised, dial-back address (from hello)
	writeMu    sync.Mutex
}

func newPeer(conn net.Conn) *Peer {
	return &Peer{conn: conn}
}

func (p *Peer) send(env envelope) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(ioTimeout))
	return writeFrame(p.conn, env)
}

func (p *Peer) recv() (envelope, error) {
	_ = p.conn.SetReadDeadline(time.Now().Add(ioTimeout * 4)) // idle peers may go quiet between gossip events
	return readFrame(p.conn)
}

func (p *Peer) close() error {
	return p.conn.Close()
}
