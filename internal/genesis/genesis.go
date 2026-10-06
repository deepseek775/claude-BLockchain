// Package genesis loads the initial chain configuration: the starting
// validator set, account balances, and consensus timing/economic
// parameters. Every node in a network must load byte-identical genesis
// data or their chains will fork immediately (the genesis block's hash
// will differ).
package genesis

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"claude-blockchain/internal/types"
)

// ProtocolVersion identifies the consensus/wire-format rule set this build
// implements. Bump it whenever a change is consensus-breaking (would cause
// an old and new node to disagree on whether a block is valid) so mixed
// versions fail loudly instead of silently forking. Genesis files pin the
// version they were written for; a node refuses to load a genesis file
// written for a version it doesn't implement.
const ProtocolVersion = 1

// Account describes one pre-funded, pre-staked validator at genesis.
type Account struct {
	Address   string `json:"address"`
	PublicKey string `json:"public_key"` // hex-encoded ed25519 public key
	Balance   uint64 `json:"balance"`
	Stake     uint64 `json:"stake"`
}

// Genesis is the network's shared starting configuration.
type Genesis struct {
	ProtocolVersion   int    `json:"protocol_version"`
	ChainID           string `json:"chain_id"`
	Timestamp         int64  `json:"timestamp"`
	BlockTimeSeconds  int    `json:"block_time_seconds"`
	MaxTxPerBlock     int    `json:"max_tx_per_block"`
	MaxBlockBytes     int    `json:"max_block_bytes"`
	MinFee            uint64 `json:"min_fee"`
	MinValidatorStake uint64 `json:"min_validator_stake"`
	// FinalityDepth is how many blocks deep a block must be before it is
	// treated as irreversible: a competing chain, however long, is
	// rejected if accepting it would rewrite a block more than this many
	// blocks behind the current head. Without this, proof-of-stake chains
	// are vulnerable to "long-range attacks" - because proposing a block
	// costs no real-world resource (unlike proof-of-work), an attacker
	// who acquires old validator keys (or a validator who signs a
	// competing history after unbonding) can costlessly build an
	// alternative chain from genesis and, absent a depth limit, present
	// it to a syncing/restarting node as the legitimate one.
	FinalityDepth uint64    `json:"finality_depth"`
	Accounts      []Account `json:"accounts"`
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
	if g.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("genesis: protocol_version %d is not supported by this build (supports %d)", g.ProtocolVersion, ProtocolVersion)
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
	if g.MaxBlockBytes <= 0 {
		g.MaxBlockBytes = 2 * 1024 * 1024 // 2MB
	}
	if g.FinalityDepth == 0 {
		g.FinalityDepth = 100
	}
	if len(g.Accounts) == 0 {
		return nil, fmt.Errorf("genesis: at least one account is required")
	}
	seen := make(map[string]bool, len(g.Accounts))
	var totalStake uint64
	var totalBalance uint64
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
		if a.Stake > 0 && a.Stake < g.MinValidatorStake {
			return nil, fmt.Errorf("genesis: account %d stake %d is below min_validator_stake %d (use 0 for a non-validating account)", i, a.Stake, g.MinValidatorStake)
		}

		var overflow bool
		totalStake, overflow = types.AddUint64(totalStake, a.Stake)
		if overflow {
			return nil, fmt.Errorf("genesis: total stake overflows")
		}
		totalBalance, overflow = types.AddUint64(totalBalance, a.Balance)
		if overflow || totalBalance > types.MaxSupply {
			return nil, fmt.Errorf("genesis: total balance exceeds max supply")
		}
	}
	if totalStake == 0 {
		return nil, fmt.Errorf("genesis: at least one account must have positive stake")
	}
	return &g, nil
}

// PublicKeyBytes decodes an account's hex public key.
func (a Account) PublicKeyBytes() ed25519.PublicKey {
	b, _ := hex.DecodeString(a.PublicKey)
	return ed25519.PublicKey(b)
}
