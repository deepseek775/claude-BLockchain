package chain

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"claude-blockchain/internal/pos"
	"claude-blockchain/internal/types"
)

// AddBlock validates block against consensus rules and current state, and
// if valid, commits it: applies its transactions, pays the proposer's
// reward, and persists it to the block log. Returns an error and leaves
// state unchanged if the block is invalid.
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
// applies its transactions (and proposer reward) to balances/nonces and
// appends it to c.blocks. Caller must hold c.mu (write lock) and is
// responsible for persistence.
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

		if err := tx.Verify(c.chainID); err != nil {
			return fmt.Errorf("block %d: tx invalid: %w", block.Index, err)
		}
		if tx.Fee < c.minFee {
			return fmt.Errorf("block %d: tx from %s pays fee %d below minimum %d", block.Index, tx.From, tx.Fee, c.minFee)
		}
		if err := c.checkTxAgainstState(tx, newBalances, newNonces); err != nil {
			return fmt.Errorf("block %d: %w", block.Index, err)
		}

		spend, _ := types.AddUint64(tx.Amount, tx.Fee) // overflow already ruled out by checkTxAgainstState
		newBalances[tx.From], _ = types.SubUint64(newBalances[tx.From], spend)
		newTo, overflow := types.AddUint64(newBalances[tx.To], tx.Amount)
		if overflow {
			return fmt.Errorf("block %d: crediting %s would overflow its balance", block.Index, tx.To)
		}
		newBalances[tx.To] = newTo
		newNonces[tx.From]++
	}

	// block.Reward was already checked (in VerifyIntegrity, called from
	// validateBlockLocked) to equal the sum of the included transactions'
	// fees, so it can be trusted here - but the credit to the proposer
	// still goes through overflow-safe arithmetic like every other balance
	// mutation.
	if block.Reward > 0 {
		newReward, overflow := types.AddUint64(newBalances[block.Validator], block.Reward)
		if overflow {
			return fmt.Errorf("block %d: crediting proposer reward would overflow validator balance", block.Index)
		}
		newBalances[block.Validator] = newReward
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
	if err := block.VerifyIntegrity(c.chainID); err != nil {
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
	if c.maxBlockBytes > 0 {
		if n, err := jsonSize(block); err != nil {
			return fmt.Errorf("block %d: failed to measure size: %w", block.Index, err)
		} else if n > c.maxBlockBytes {
			return fmt.Errorf("block %d: exceeds max block size (%d > %d bytes)", block.Index, n, c.maxBlockBytes)
		}
	}
	return nil
}

func jsonSize(v any) (int, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

// CreateBlock assembles and signs a new block proposal from candidate
// transactions. Only transactions that pass validation against the
// resulting sequential state are included; invalid ones (e.g. stale nonce,
// insufficient balance once earlier txs in the batch are applied, fee
// below the network minimum) are silently dropped rather than rejecting
// the whole block. The proposer's reward is the sum of included fees.
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
	minFee := c.minFee
	maxTx := c.maxTxPerBlock
	maxBytes := c.maxBlockBytes
	chainID := c.chainID
	c.mu.RUnlock()

	included := make([]types.Transaction, 0, len(candidates))
	var reward uint64
	approxSize := 256 // headroom for block header fields
	for _, tx := range candidates {
		if len(included) >= maxTx {
			break
		}
		if err := tx.Verify(chainID); err != nil {
			continue
		}
		if tx.Fee < minFee {
			continue
		}
		if err := c.checkTxAgainstState(tx, balances, nonces); err != nil {
			continue
		}
		txSize, err := jsonSize(tx)
		if err != nil {
			continue
		}
		if maxBytes > 0 && approxSize+txSize > maxBytes {
			break
		}

		spend, _ := types.AddUint64(tx.Amount, tx.Fee)
		balances[tx.From], _ = types.SubUint64(balances[tx.From], spend)
		newTo, overflow := types.AddUint64(balances[tx.To], tx.Amount)
		if overflow {
			continue
		}
		balances[tx.To] = newTo
		nonces[tx.From]++

		newReward, overflow := types.AddUint64(reward, tx.Fee)
		if overflow {
			break // stop including more fee-paying tx rather than risk reward overflow
		}
		reward = newReward
		approxSize += txSize
		included = append(included, tx)
	}

	block := types.Block{
		ChainID:      chainID,
		Index:        last.Index + 1,
		Timestamp:    time.Now().Unix(),
		PrevHash:     last.Hash,
		Transactions: included,
		Reward:       reward,
		Validator:    validatorAddr,
		ValidatorPub: priv.Public().(ed25519.PublicKey),
	}
	block.Sign(priv)
	return block, nil
}
