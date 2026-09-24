package p2p

import (
	"time"

	"claude-blockchain/internal/types"
)

// maybeVote signs and broadcasts this node's own commit vote for block if
// this node has a wallet with stake (i.e. is a validator). It's called
// after any block is committed - whether proposed by this node, received
// from a peer, or adopted via a chain sync - so every validator attests to
// every block it accepts, which is what lets the network reach >2/3-stake
// finality quickly. Voting is idempotent per (voter, height): the chain
// dedups by voter address, so calling this more than once for the same
// block is harmless.
func (n *Node) maybeVote(block types.Block) {
	if n.cfg.Wallet == nil {
		return
	}
	if n.cfg.Chain.GetStake(n.cfg.Wallet.Address) == 0 {
		return
	}

	v := types.Vote{
		ChainID:   n.cfg.Chain.ChainID(),
		BlockHash: block.Hash,
		Height:    block.Index,
		Voter:     n.cfg.Wallet.Address,
	}
	v.Sign(n.cfg.Wallet.PrivateKey)

	if _, err := n.cfg.Chain.AddVote(v); err != nil {
		n.log.Printf("p2p: failed to record own vote for block %d: %v", block.Index, err)
		return
	}
	n.markSeenVote(v.Hash())

	env, err := newEnvelope(msgVote, v)
	if err != nil {
		return
	}
	n.broadcast(env, nil)
}

// handleVote validates and records a vote from a peer, gossiping it onward
// if it's new. finalization is logged here (and in handleBlock/handleChain)
// by comparing FinalizedHeight before/after, since a vote received now may
// finalize a block whether it was buffered pending a block we didn't have
// yet or applies immediately.
func (n *Node) handleVote(v types.Vote, from *Peer) {
	h := v.Hash()
	if n.alreadySeenVote(h) {
		return
	}
	n.markSeenVote(h)

	before := n.cfg.Chain.FinalizedHeight()
	if _, err := n.cfg.Chain.AddVote(v); err != nil {
		n.log.Printf("p2p: rejected vote from %s: %v", v.Voter, err)
		return
	}

	env, err := newEnvelope(msgVote, v)
	if err == nil {
		n.broadcast(env, from)
	}
	n.logFinalization(before)
}

// logFinalization reports a finality advance to the operator log, if one
// happened since before.
func (n *Node) logFinalization(before uint64) {
	if after := n.cfg.Chain.FinalizedHeight(); after > before {
		n.log.Printf("p2p: block %d finalized (>2/3 stake attested)", after)
	}
}

func (n *Node) alreadySeenVote(h [32]byte) bool {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	_, ok := n.seenVotes[h]
	return ok
}

func (n *Node) markSeenVote(h [32]byte) {
	n.seenMu.Lock()
	defer n.seenMu.Unlock()
	n.seenVotes[h] = time.Now()
}
