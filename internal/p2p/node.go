package p2p

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"claude-blockchain/internal/chain"
	"claude-blockchain/internal/mempool"
	"claude-blockchain/internal/types"
	"claude-blockchain/internal/wallet"
)

// defaultMaxPeers caps how many simultaneous peer connections a node keeps.
// This bounds memory/goroutine/file-descriptor usage under a connection
// flood and keeps gossip fan-out cheap.
const defaultMaxPeers = 32

// gossipTTL is how long a transaction/block hash is remembered in the
// dedup cache. Long enough to suppress re-broadcast loops across a slow
// mesh, short enough that the cache doesn't grow without bound.
const gossipTTL = 10 * time.Minute

// Config configures a Node.
type Config struct {
	ListenAddr     string   // e.g. ":26656"
	AdvertiseAddr  string   // address peers should dial to reach us, e.g. "node1:26656"
	BootstrapPeers []string // addresses to connect to on startup
	MaxPeers       int

	Chain   *chain.Chain
	Mempool *mempool.Mempool
	Wallet  *wallet.Wallet // nil => this node never proposes blocks

	Logger *log.Logger
}

// Node runs the P2P gossip network and, if configured with a wallet whose
// address holds stake, the block-proposal loop.
type Node struct {
	cfg Config
	log *log.Logger

	mu    sync.Mutex
	peers map[string]*Peer // key: advertised dial-back address

	seenMu     sync.Mutex
	seenTx     map[[32]byte]time.Time
	seenBlocks map[string]time.Time

	// proposeMu prevents the ticker-driven and event-driven (post-sync,
	// post-new-block) calls to tryPropose from racing each other into
	// proposing two blocks for the same height.
	proposeMu sync.Mutex
}

func New(cfg Config) *Node {
	if cfg.MaxPeers <= 0 {
		cfg.MaxPeers = defaultMaxPeers
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	return &Node{
		cfg:        cfg,
		log:        cfg.Logger,
		peers:      make(map[string]*Peer),
		seenTx:     make(map[[32]byte]time.Time),
		seenBlocks: make(map[string]time.Time),
	}
}

// Run starts the listener, dials bootstrap peers, and runs the proposal
// loop until ctx is cancelled.
func (n *Node) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", n.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", n.cfg.ListenAddr, err)
	}
	n.log.Printf("p2p: listening on %s (advertising %s)", n.cfg.ListenAddr, n.cfg.AdvertiseAddr)

	go n.acceptLoop(ctx, ln)
	go n.gossipJanitor(ctx)
	go n.proposalLoop(ctx)

	for _, addr := range n.cfg.BootstrapPeers {
		addr := addr
		go n.dial(ctx, addr)
	}

	<-ctx.Done()
	ln.Close()
	return nil
}

func (n *Node) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				n.log.Printf("p2p: accept error: %v", err)
				return
			}
		}
		go n.handleConn(ctx, conn, "")
	}
}

func (n *Node) dial(ctx context.Context, addr string) {
	if addr == n.cfg.AdvertiseAddr {
		return
	}
	conn, err := net.DialTimeout("tcp", addr, ioTimeout)
	if err != nil {
		n.log.Printf("p2p: dial %s failed: %v", addr, err)
		return
	}
	n.handleConn(ctx, conn, addr)
}

// handleConn drives one connection's lifecycle: hello handshake, then a
// read loop dispatching envelopes until the connection closes. knownAddr is
// set when we dialed this peer ourselves (so we already know its address);
// it is empty for inbound connections until their hello arrives.
func (n *Node) handleConn(ctx context.Context, conn net.Conn, knownAddr string) {
	peer := newPeer(conn)
	defer peer.close()

	hello, _ := newEnvelope(msgHello, helloMsg{
		ChainID:    n.cfg.Chain.ChainID(),
		ListenAddr: n.cfg.AdvertiseAddr,
	})
	if err := peer.send(hello); err != nil {
		return
	}

	var registered bool
	var peerAddr string
	defer func() {
		if registered {
			n.removePeer(peerAddr)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		env, err := peer.recv()
		if err != nil {
			return
		}

		switch env.Type {
		case msgHello:
			var h helloMsg
			if err := json.Unmarshal(env.Data, &h); err != nil {
				return
			}
			if h.ChainID != n.cfg.Chain.ChainID() {
				n.log.Printf("p2p: peer %s has mismatched chain_id %q, disconnecting", conn.RemoteAddr(), h.ChainID)
				return
			}
			addr := knownAddr
			if addr == "" {
				addr = h.ListenAddr
			}
			// An empty advertised ListenAddr marks an ephemeral client
			// (e.g. the `tx` CLI) that only wants to submit a message and
			// is not a routable peer: don't register it, don't gossip
			// list it, and don't count it against MaxPeers.
			if addr != "" && addr != n.cfg.AdvertiseAddr {
				if n.addPeer(addr, peer) {
					registered = true
					peerAddr = addr
					n.log.Printf("p2p: connected to peer %s", addr)
					n.requestPeers(peer)
					n.requestChainIfBehind(peer)
				} else {
					return
				}
			}

		case msgGetPeers:
			n.handleGetPeers(peer)

		case msgPeers:
			var pm peersMsg
			if err := json.Unmarshal(env.Data, &pm); err != nil {
				continue
			}
			n.handlePeers(ctx, pm)

		case msgTx:
			var tx types.Transaction
			if err := json.Unmarshal(env.Data, &tx); err != nil {
				continue
			}
			n.handleTx(tx, peer)

		case msgBlock:
			var b types.Block
			if err := json.Unmarshal(env.Data, &b); err != nil {
				continue
			}
			n.handleBlock(b, peer)

		case msgGetChain:
			n.handleGetChain(peer)

		case msgGetAccount:
			var req getAccountMsg
			if err := json.Unmarshal(env.Data, &req); err != nil {
				continue
			}
			n.handleGetAccount(peer, req.Address)

		case msgChain:
			var blocks []types.Block
			if err := json.Unmarshal(env.Data, &blocks); err != nil {
				continue
			}
			n.handleChain(blocks)

		default:
			// Unknown message types are ignored rather than treated as
			// fatal, so the protocol can grow without breaking old peers.
		}
	}
}

func (n *Node) addPeer(addr string, p *Peer) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.peers[addr]; ok {
		return false // already connected to this peer via another connection
	}
	if len(n.peers) >= n.cfg.MaxPeers {
		return false
	}
	p.remoteAddr = addr
	n.peers[addr] = p
	return true
}

func (n *Node) removePeer(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, addr)
}

func (n *Node) peerList() []*Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		out = append(out, p)
	}
	return out
}

func (n *Node) peerAddrs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.peers))
	for a := range n.peers {
		out = append(out, a)
	}
	return out
}

// broadcast sends env to every connected peer except exclude.
func (n *Node) broadcast(env envelope, exclude *Peer) {
	for _, p := range n.peerList() {
		if p == exclude {
			continue
		}
		if err := p.send(env); err != nil {
			n.log.Printf("p2p: send to %s failed: %v", p.remoteAddr, err)
		}
	}
}
