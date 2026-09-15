package chain

import (
	"fmt"

	"claude-blockchain/internal/types"
)

// ReplaceChain validates candidate as a full replacement chain and, if it
// is both valid and longer than the current chain, atomically swaps it in
// (fork choice rule: longest valid chain, bounded by finality - see below).
// It is used when a peer reports a chain ahead of ours.
//
// The genesis block must exactly match ours (same hash, which also encodes
// ChainID) - otherwise the candidate belongs to a different network and is
// rejected regardless of length.
//
// Finality: if candidate diverges from our chain at some block more than
// FinalityDepth blocks behind our current head, it is rejected even if
// longer and otherwise valid. Without this, a proof-of-stake chain (unlike
// proof-of-work) can be costlessly rewritten arbitrarily far back by anyone
// who holds - or once held - validator keys, since producing an alternate
// history requires no real-world resource once a private key is known. A
// depth limit converts "anything longer wins" into "anything longer wins,
// as long as it doesn't rewrite blocks we already treat as settled" -
// matching how real payment systems reason about settlement finality.
func (c *Chain) ReplaceChain(candidate []types.Block) error {
	if len(candidate) == 0 {
		return fmt.Errorf("candidate chain is empty")
	}

	c.mu.RLock()
	ourBlocks := make([]types.Block, len(c.blocks))
	copy(ourBlocks, c.blocks)
	startBalances := cloneU64Map(c.genesisBalances)
	startStakes := cloneU64Map(c.stakes)
	c.mu.RUnlock()

	ourGenesis := ourBlocks[0]
	ourLen := len(ourBlocks)

	if candidate[0].Hash != ourGenesis.Hash || candidate[0].Index != 0 {
		return fmt.Errorf("candidate chain has different genesis")
	}
	if len(candidate) <= ourLen {
		return fmt.Errorf("candidate chain (len %d) is not longer than current (len %d)", len(candidate), ourLen)
	}

	commonLen := 0
	minLen := ourLen
	if len(candidate) < minLen {
		minLen = len(candidate)
	}
	for commonLen < minLen && ourBlocks[commonLen].Hash == candidate[commonLen].Hash {
		commonLen++
	}
	reorgDepth := ourLen - commonLen
	if uint64(reorgDepth) > c.finalityDepth {
		return fmt.Errorf("candidate chain would rewrite %d already-finalized blocks (max reorg depth: %d) - rejected", reorgDepth, c.finalityDepth)
	}

	// Re-derive state from scratch by replaying every block through the
	// same validation used for a live-appended block. This guarantees a
	// synced chain is exactly as trustworthy as one built block-by-block.
	// sim must mirror every consensus/economic parameter c uses during
	// validation (not just chainID) - otherwise a synced chain could be
	// accepted under laxer rules than a live block would be.
	sim := &Chain{
		chainID:       c.chainID,
		blockTime:     c.blockTime,
		maxTxPerBlock: c.maxTxPerBlock,
		maxBlockBytes: c.maxBlockBytes,
		minFee:        c.minFee,
		finalityDepth: c.finalityDepth,
		blocks:        []types.Block{candidate[0]},
		balances:      startBalances,
		nonces:        make(map[string]uint64),
		stakes:        startStakes,
		validatorPubs: c.validatorPubs,
	}
	for _, block := range candidate[1:] {
		if err := sim.applyBlockLocked(block); err != nil {
			return fmt.Errorf("candidate chain invalid at block %d: %w", block.Index, err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(candidate) <= len(c.blocks) {
		// Lost a race with a concurrent update; nothing to do.
		return nil
	}
	c.blocks = sim.blocks
	c.balances = sim.balances
	c.nonces = sim.nonces

	if c.logFile != nil {
		if err := c.rewriteLog(); err != nil {
			return fmt.Errorf("chain replaced but failed to persist: %w", err)
		}
	}
	return nil
}

func cloneU64Map(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
