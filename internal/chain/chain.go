// Package chain holds the canonical blockchain state: the block list,
// account balances, nonces, and validator stakes, plus the validation
// rules that keep every honest node's copy identical.
package chain

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"claude-blockchain/internal/genesis"
	"claude-blockchain/internal/pos"
	"claude-blockchain/internal/types"
)

// maxClockSkew bounds how far a proposed block's timestamp may drift from
// the local wall clock, in either direction. This limits a malicious
// validator's ability to warp the chain's apparent timeline and blocks
// trivially stale/far-future block replay.
const maxClockSkew = 30 * time.Second

// Chain is the append-only, validated block log plus derived account state.
// All exported methods are safe for concurrent use.
type Chain struct {
	mu sync.RWMutex

	chainID       string
	blockTime     time.Duration
	maxTxPerBlock int

	blocks []types.Block

	balances      map[string]uint64
	nonces        map[string]uint64
	stakes        map[string]uint64
	validatorPubs map[string]ed25519.PublicKey

	// genesisBalances is retained separately from balances (which mutates
	// as blocks apply) so that a full chain re-sync (see ReplaceChain) can
	// replay state from the correct starting point. Note: this demo chain
	// does not implement dynamic staking transactions, so stakes never
	// change after genesis and don't need the same treatment.
	genesisBalances map[string]uint64

	logFile *os.File // append-only persisted copy of blocks, one JSON line each
}

// New builds a chain from genesis configuration and, if logPath is
// non-empty, replays/opens a persisted block log so the node can resume
// after a restart without re-syncing from peers.
func New(g *genesis.Genesis, logPath string) (*Chain, error) {
	c := &Chain{
		chainID:       g.ChainID,
		blockTime:     time.Duration(g.BlockTimeSeconds) * time.Second,
		maxTxPerBlock: g.MaxTxPerBlock,
		balances:      make(map[string]uint64),
		nonces:        make(map[string]uint64),
		stakes:        make(map[string]uint64),
		validatorPubs: make(map[string]ed25519.PublicKey),
	}
	for _, a := range g.Accounts {
		c.balances[a.Address] = a.Balance
		c.stakes[a.Address] = a.Stake
		c.validatorPubs[a.Address] = a.PublicKeyBytes()
	}
	c.genesisBalances = cloneU64Map(c.balances)

	genesisBlock := types.Block{
		Index:     0,
		Timestamp: g.Timestamp,
		PrevHash:  strings.Repeat("0", 64),
	}
	genesisBlock.Hash = genesisBlock.ComputeHash()
	c.blocks = append(c.blocks, genesisBlock)

	if logPath != "" {
		if err := c.openLog(logPath); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Chain) ChainID() string              { return c.chainID }
func (c *Chain) BlockInterval() time.Duration { return c.blockTime }
func (c *Chain) MaxTxPerBlock() int           { return c.maxTxPerBlock }

// Height returns the index of the latest block.
func (c *Chain) Height() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[len(c.blocks)-1].Index
}

// LastBlock returns a copy of the most recently committed block.
func (c *Chain) LastBlock() types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocks[len(c.blocks)-1]
}

// Len returns the number of blocks, including genesis.
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.blocks)
}

// Blocks returns a copy of the full chain (for peer sync responses).
func (c *Chain) Blocks() []types.Block {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]types.Block, len(c.blocks))
	copy(out, c.blocks)
	return out
}

func (c *Chain) GetBalance(addr string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.balances[addr]
}

func (c *Chain) GetNonce(addr string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.nonces[addr]
}

func (c *Chain) GetStake(addr string) uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stakes[addr]
}

// Stakes returns a copy of the current stake table.
func (c *Chain) Stakes() map[string]uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]uint64, len(c.stakes))
	for k, v := range c.stakes {
		out[k] = v
	}
	return out
}

// ExpectedValidator returns the address that must propose the next block,
// given the current chain head.
func (c *Chain) ExpectedValidator() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	last := c.blocks[len(c.blocks)-1]
	return pos.SelectValidator(last.Hash, last.Index+1, c.stakes)
}

// ValidateTransaction performs stateless signature/shape checks plus
// stateful balance and nonce checks against current committed state. It
// does not mutate state or consider transactions already sitting in the
// mempool, so callers building a block must also guard against multiple
// pooled transactions from the same sender racing the same nonce (see
// applyBlockLocked, which re-checks nonces sequentially while building the
// new state).
func (c *Chain) ValidateTransaction(tx types.Transaction) error {
	if err := tx.Verify(); err != nil {
		return err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.checkTxAgainstState(tx, c.balances, c.nonces)
}

func (c *Chain) checkTxAgainstState(tx types.Transaction, balances, nonces map[string]uint64) error {
	if nonces[tx.From] != tx.Nonce {
		return fmt.Errorf("tx from %s: expected nonce %d, got %d", tx.From, nonces[tx.From], tx.Nonce)
	}
	if balances[tx.From] < tx.Amount {
		return fmt.Errorf("tx from %s: insufficient balance (%d < %d)", tx.From, balances[tx.From], tx.Amount)
	}
	return nil
}
