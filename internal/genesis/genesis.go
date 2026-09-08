// Package genesis loads the initial chain configuration: the starting
// validator set, account balances, and consensus timing parameters. Every
// node in a network must load byte-identical genesis data or their chains
// will fork immediately (the genesis block's hash will differ).
package genesis

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"claude-blockchain/internal/types"
)

// Account describes one pre-funded, pre-staked validator at genesis.
type Account struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"` // hex-encoded ed25519 public key
	Balance   uint64 `json:"balance"`
	Stake     uint64 `json:"stake"`
}

// Genesis is the network's shared starting configuration.
type Genesis struct {
	ChainID          string    `json:"chain_id"`
	Timestamp        int64     `json:"timestamp"`
	BlockTimeSeconds int       `json:"block_time_seconds"`
	MaxTxPerBlock    int       `json:"max_tx_per_block"`
	Accounts         []Account `json:"accounts"`
}

// Load reads and validates a genesis file.
func Load(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g Genesis
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("parse genesis: %w", err)
	}
	if g.ChainID == "" {
		return nil, fmt.Errorf("genesis: chain_id is required")
	}
	if g.BlockTimeSeconds <= 0 {
		g.BlockTimeSeconds = 5
	}
	if g.MaxTxPerBlock <= 0 {
		g.MaxTxPerBlock = 500
	}
	if len(g.Accounts) == 0 {
		return nil, fmt.Errorf("genesis: at least one account is required")
	}
	seen := make(map[string]bool, len(g.Accounts))
	var totalStake uint64
	for i := range g.Accounts {
		a := &g.Accounts[i]
		pubBytes, err := hex.DecodeString(a.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("genesis: account %d has invalid public_key", i)
		}
		if err := types.CheckAddress(a.Address, ed25519.PublicKey(pubBytes)); err != nil {
			return nil, fmt.Errorf("genesis: account %d: %w", i, err)
		}
		if seen[a.Address] {
			return nil, fmt.Errorf("genesis: duplicate account %s", a.Address)
		}
		seen[a.Address] = true
		totalStake += a.Stake
	}
	if totalStake == 0 {
		return nil, fmt.Errorf("genesis: at least one account must have positive stake")
	}
	return &g, nil
}

// PublicKey decodes an account's hex public key.
func (a Account) PublicKeyBytes() ed25519.PublicKey {
	b, _ := hex.DecodeString(a.PublicKey)
	return ed25519.PublicKey(b)
}
