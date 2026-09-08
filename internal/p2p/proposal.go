package p2p

import (
	"context"
	"time"
)

// proposalLoop is a heartbeat fallback: tryPropose is also triggered
// immediately after this node accepts a new block or completes a chain
// sync, so in a healthy network proposals happen promptly rather than
// waiting for the next tick. The ticker exists so a validator whose turn
// comes up while the network is otherwise quiet (empty mempool, no
// incoming blocks) still proposes.
func (n *Node) proposalLoop(ctx context.Context) {
	if n.cfg.Wallet == nil {
		return
	}
	interval := n.cfg.Chain.BlockInterval()
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.tryPropose()
		}
	}
}

// tryPropose builds, signs, commits, and broadcasts a new block if this
// node's wallet address is the validator selected for the current next
// height. It is a no-op otherwise.
func (n *Node) tryPropose() {
	if n.cfg.Wallet == nil {
		return
	}
	n.proposeMu.Lock()
	defer n.proposeMu.Unlock()

	expected := n.cfg.Chain.ExpectedValidator()
	if expected == "" || expected != n.cfg.Wallet.Address {
		return
	}

	candidates := n.cfg.Mempool.Take(n.cfg.Chain.MaxTxPerBlock())
	block, err := n.cfg.Chain.CreateBlock(candidates, n.cfg.Wallet.Address, n.cfg.Wallet.PrivateKey)
	if err != nil {
		n.log.Printf("p2p: failed to build block proposal: %v", err)
		return
	}
	if err := n.cfg.Chain.AddBlock(block); err != nil {
		n.log.Printf("p2p: failed to commit own block proposal: %v", err)
		return
	}
	n.cfg.Mempool.Remove(block.Transactions)
	n.markSeenBlock(block.Hash)
	n.log.Printf("p2p: proposed block %d (%d tx)", block.Index, len(block.Transactions))

	env, err := newEnvelope(msgBlock, block)
	if err != nil {
		return
	}
	n.broadcast(env, nil)
}
