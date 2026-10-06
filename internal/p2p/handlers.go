package p2p

import (
	"context"
	"time"

	"claude-blockchain/internal/types"
)

func (n *Node) requestPeers(p *Peer) {
	env, _ := newEnvelope(msgGetPeers, nil)
	_ = p.send(env)
}

func (n *Node) handleGetPeers(p *Peer) {
	env, _ := newEnvelope(msgPeers, peersMsg{Addrs: n.peerAddrs()})
	_ = p.send(env)
}

func (n *Node) handlePeers(ctx context.Context, pm peersMsg) {
	existing := make(map[string]bool)
	for _, a := range n.peerAddrs() {
		existing[a] = true
	}
	for _, addr := range pm.Addrs {
		if addr == "" || addr == n.cfg.AdvertiseAddr || existing[addr] {
			continue
		}
		go n.dial(ctx, addr)
	}
}

// requestChainIfBehind asks p for its full chain if we appear to be behind
// (best-effort: we only really know once we see a block or chain from it,
// but asking a freshly connected peer up front lets us catch up quickly
// after startup rather than waiting for the next proposed block).
func (n *Node) requestChainIfBehind(p *Peer) {
	env, _ := newEnvelope(msgGetChain, nil)
	_ = p.send(env)
}

func (n *Node) handleGetChain(p *Peer) {
	env, _ := newEnvelope(msgChain, n.cfg.Chain.Blocks())
	_ = p.send(env)
}

func (n *Node) handleGetAccount(p *Peer, addr string) {
	info := AccountInfo{
		Address: addr,
		Balance: n.cfg.Chain.GetBalance(addr),
		Nonce:   n.cfg.Chain.GetNonce(addr),
		Stake:   n.cfg.Chain.GetStake(addr),
	}
	env, _ := newEnvelope(msgAccount, info)
	_ = p.send(env)
}

func (n *Node) handleChain(blocks []types.Block) {
	if len(blocks) <= n.cfg.Chain.Len() {
		return
	}
	before := n.cfg.Chain.FinalizedHeight()
	if err := n.cfg.Chain.ReplaceChain(blocks); err != nil {
		n.log.Printf("p2p: rejected chain sync: %v", err)
		return
	}
	n.log.Printf("p2p: synced chain to height %d", n.cfg.Chain.Height())
	n.maybeVote(n.cfg.Chain.LastBlock()) // attest to the new tip so it can start collecting finality votes
	n.logFinalization(before)
	n.tryPropose() // we may now be the expected proposer for the new head
}

// handleTx validates and pools tx, gossiping it onward if it's new and
// valid. It reports back whether the transaction was accepted so a direct
// submitter (see the `tx` CLI / msgTxResult) gets real feedback instead of
// a submission that silently vanishes on rejection.
func (n *Node) handleTx(tx types.Transaction, from *Peer) (accepted bool, reason string) {
	h := tx.Hash()
	if n.alreadySeenTx(h) {
		return false, "already seen"
	}
	n.markSeenTx(h)

	if err := n.cfg.Chain.ValidateTransactionStateless(tx); err != nil {
		n.log.Printf("p2p: rejected tx from %s: %v", tx.From, err)
		return false, err.Error()
	}
	chainNonce := n.cfg.Chain.GetNonce(tx.From)
	chainBalance := n.cfg.Chain.GetBalance(tx.From)
	ok, reason := n.cfg.Mempool.Add(tx, chainNonce, chainBalance)
	if !ok {
		return false, reason
	}
	env, _ := newEnvelope(msgTx, tx)
	n.broadcast(env, from)
	return true, ""
}

func (n *Node) handleGetParams(p *Peer) {
	params := NetworkParams{
		ChainID:         n.cfg.Chain.ChainID(),
		MinFee:          n.cfg.Chain.MinFee(),
		MaxTxPerBlock:   n.cfg.Chain.MaxTxPerBlock(),
		MaxBlockBytes:   n.cfg.Chain.MaxBlockBytes(),
		FinalityDepth:   n.cfg.Chain.FinalityDepth(),
		BlockSeconds:    int(n.cfg.Chain.BlockInterval().Seconds()),
		FinalizedHeight: n.cfg.Chain.FinalizedHeight(),
	}
	env, _ := newEnvelope(msgParams, params)
	_ = p.send(env)
}

func (n *Node) handleBlock(b types.Block, from *Peer) {
	if n.alreadySeenBlock(b.Hash) {
		return
	}
	n.markSeenBlock(b.Hash)

	height := n.cfg.Chain.Height()
	switch {
	case b.Index <= height:
		return // stale, already have it
	case b.Index > height+1:
		// We're missing intermediate blocks; ask this peer for its whole
		// chain rather than trying to buffer out-of-order blocks.
		env, _ := newEnvelope(msgGetChain, nil)
		_ = from.send(env)
		return
	}

	before := n.cfg.Chain.FinalizedHeight()
	if err := n.cfg.Chain.AddBlock(b); err != nil {
		n.log.Printf("p2p: rejected block %d from peer: %v", b.Index, err)
		return
	}
	n.cfg.Mempool.Remove(b.Transactions)
	n.log.Printf("p2p: accepted block %d (validator %s, %d tx)", b.Index, b.Validator, len(b.Transactions))

	env, _ := newEnvelope(msgBlock, b)
	n.broadcast(env, from)

	n.maybeVote(b)
	n.logFinalization(before)
	n.tryPropose() // we may be the expected proposer for the next height
}

// --- gossip dedup cache ---

func (n *Node) alreadySeenTx(h [32]byte) bool {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	_, ok := n.seenTx[h]
	return ok
}

func (n *Node) markSeenTx(h [32]byte) {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	n.seenTx[h] = time.Now()
}

func (n *Node) alreadySeenBlock(hash string) bool {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	_, ok := n.seenBlocks[hash]
	return ok
}

func (n *Node) markSeenBlock(hash string) {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	n.seenBlocks[hash] = time.Now()
}

// gossipJanitor periodically evicts old entries from the seen-tx/block
// caches so long-running nodes don't accumulate unbounded memory.
func (n *Node) gossipJanitor(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			n.seenMu.Lock()
			for h, t := range n.seenTx {
				if now.Sub(t) > gossipTTL {
					delete(n.seenTx, h)
				}
			}
			for h, t := range n.seenBlocks {
				if now.Sub(t) > gossipTTL {
					delete(n.seenBlocks, h)
				}
			}
			for h, t := range n.seenVotes {
				if now.Sub(t) > gossipTTL {
					delete(n.seenVotes, h)
				}
			}
			n.seenMu.Unlock()
		}
	}
}
