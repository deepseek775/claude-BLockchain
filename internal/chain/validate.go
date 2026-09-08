package chain

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"claude-blockchain/internal/pos"
	"claude-blockchain/internal/types"
)

// AddBlock validates block against consensus rules and current state, and
// if valid, commits it: applies its transactions, updates the stake table,
// and persists it to the block log. Returns an error and leaves state
// unchanged if the block is invalid.
func (c *Chain) AddBlock(block types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.applyBlockLocked(block); err != nil {
		return err
	}

	if c.logFile != nil {
		if err := c.appendLog(block); err != nil {
			// Persistence failure shouldn't roll back an already-valid,
			// already-committed block (peers have accepted it too, and
			// this node's own signature may already be on it) - surface
			// the error to the caller for logging, but keep the in-memory
			// state committed.
			return fmt.Errorf("block %d committed but failed to persist: %w", block.Index, err)
		}
	}
	return nil
}

// applyBlockLocked validates block against consensus rules and, if valid,
// applies its transactions to balances/nonces and appends it to c.blocks.
// Caller must hold c.mu (write lock) and is responsible for persistence.
func (c *Chain) applyBlockLocked(block types.Block) error {
	last := c.blocks[len(c.blocks)-1]
	if err := c.validateBlockLocked(block, last); err != nil {
		return err
	}

	newBalances := make(map[string]uint64, len(c.balances))
	for k, v := range c.balances {
		newBalances[k] = v
	}
	newNonces := make(map[string]uint64, len(c.nonces))
	for k, v := range c.nonces {
		newNonces[k] = v
	}

	seen := make(map[[32]byte]bool, len(block.Transactions))
	for _, tx := range block.Transactions {
		h := tx.Hash()
		if seen[h] {
			return fmt.Errorf("block %d: duplicate transaction in block", block.Index)
		}
		seen[h] = true

		if err := tx.Verify(); err != nil {
			return fmt.Errorf("block %d: tx invalid: %w", block.Index, err)
		}
		if err := c.checkTxAgainstState(tx, newBalances, newNonces); err != nil {
			return fmt.Errorf("block %d: %w", block.Index, err)
		}
		newBalances[tx.From] -= tx.Amount
		newBalances[tx.To] += tx.Amount
		newNonces[tx.From]++
	}

	c.balances = newBalances
	c.nonces = newNonces
	c.blocks = append(c.blocks, block)
	return nil
}

// validateBlockLocked checks consensus rules. Caller must hold c.mu.
func (c *Chain) validateBlockLocked(block types.Block, last types.Block) error {
	if block.Index != last.Index+1 {
		return fmt.Errorf("block index %d does not follow last index %d", block.Index, last.Index)
	}
	if block.PrevHash != last.Hash {
		return fmt.Errorf("block %d: prev_hash does not match chain head", block.Index)
	}
	now := time.Now().Unix()
	skew := int64(maxClockSkew.Seconds())
	if block.Timestamp > now+skew || block.Timestamp < last.Timestamp {
		return fmt.Errorf("block %d: timestamp %d out of acceptable range", block.Index, block.Timestamp)
	}
	if err := block.VerifyIntegrity(); err != nil {
		return fmt.Errorf("block %d: %w", block.Index, err)
	}

	expected := pos.SelectValidator(last.Hash, block.Index, c.stakes)
	if expected == "" {
		return fmt.Errorf("block %d: no eligible validator", block.Index)
	}
	if block.Validator != expected {
		return fmt.Errorf("block %d: proposed by %s, expected validator %s", block.Index, block.Validator, expected)
	}
	if pub, ok := c.validatorPubs[block.Validator]; ok && !pub.Equal(block.ValidatorPub) {
		return fmt.Errorf("block %d: validator public key does not match known key for %s", block.Index, block.Validator)
	}
	if len(block.Transactions) > c.maxTxPerBlock {
		return fmt.Errorf("block %d: exceeds max transactions per block (%d > %d)", block.Index, len(block.Transactions), c.maxTxPerBlock)
	}
	return nil
}

// CreateBlock assembles and signs a new block proposal from candidate
// transactions. Only transactions that pass validation against the
// resulting sequential state are included; invalid ones (e.g. stale nonce,
// insufficient balance once earlier txs in the batch are applied) are
// silently dropped rather than rejecting the whole block.
func (c *Chain) CreateBlock(candidates []types.Transaction, validatorAddr string, priv ed25519.PrivateKey) (types.Block, error) {
	c.mu.RLock()
	last := c.blocks[len(c.blocks)-1]
	balances := make(map[string]uint64, len(c.balances))
	for k, v := range c.balances {
		balances[k] = v
	}
	nonces := make(map[string]uint64, len(c.nonces))
	for k, v := range c.nonces {
		nonces[k] = v
	}
	c.mu.RUnlock()

	included := make([]types.Transaction, 0, len(candidates))
	for _, tx := range candidates {
		if len(included) >= c.maxTxPerBlock {
			break
		}
		if err := tx.Verify(); err != nil {
			continue
		}
		if err := c.checkTxAgainstState(tx, balances, nonces); err != nil {
			continue
		}
		balances[tx.From] -= tx.Amount
		balances[tx.To] += tx.Amount
		nonces[tx.From]++
		included = append(included, tx)
	}

	block := types.Block{
		Index:        last.Index + 1,
		Timestamp:    time.Now().Unix(),
		PrevHash:     last.Hash,
		Transactions: included,
		Validator:    validatorAddr,
		ValidatorPub: priv.Public().(ed25519.PublicKey),
	}
	block.Sign(priv)
	return block, nil
}
