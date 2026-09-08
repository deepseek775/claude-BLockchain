package chain

import (
	"fmt"

	"claude-blockchain/internal/types"
)

// ReplaceChain validates candidate as a full replacement chain and, if it
// is both valid and longer than the current chain, atomically swaps it in
// (fork choice rule: longest valid chain). It is used when a peer reports a
// chain ahead of ours.
//
// The genesis block must exactly match ours (same hash) - otherwise the
// candidate belongs to a different network/genesis and is rejected
// regardless of length.
func (c *Chain) ReplaceChain(candidate []types.Block) error {
	if len(candidate) == 0 {
		return fmt.Errorf("candidate chain is empty")
	}

	c.mu.RLock()
	ourGenesis := c.blocks[0]
	ourLen := len(c.blocks)
	c.mu.RUnlock()

	if candidate[0].Hash != ourGenesis.Hash || candidate[0].Index != 0 {
		return fmt.Errorf("candidate chain has different genesis")
	}
	if len(candidate) <= ourLen {
		return fmt.Errorf("candidate chain (len %d) is not longer than current (len %d)", len(candidate), ourLen)
	}

	// Re-derive state from scratch by replaying every block through the
	// same validation used for a live-appended block. This guarantees a
	// synced chain is exactly as trustworthy as one built block-by-block.
	c.mu.RLock()
	startBalances := cloneU64Map(c.genesisBalances)
	startStakes := cloneU64Map(c.stakes)
	c.mu.RUnlock()

	sim := &Chain{
		chainID:       c.chainID,
		blockTime:     c.blockTime,
		maxTxPerBlock: c.maxTxPerBlock,
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
