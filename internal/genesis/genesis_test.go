package genesis

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"claude-blockchain/internal/types"
)

func writeGenesis(t *testing.T, g Genesis) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "genesis.json")
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testAccount(t *testing.T, balance, stake uint64) Account {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return Account{
		Address:   types.AddressFromPubKey(pub),
		PublicKey: hex.EncodeToString(pub),
		Balance:   balance,
		Stake:     stake,
	}
}

func baseGenesis(accounts ...Account) Genesis {
	return Genesis{
		ProtocolVersion: ProtocolVersion,
		ChainID:         "unit-test",
		Timestamp:       time.Now().Unix(),
		Accounts:        accounts,
	}
}

func TestLoadValidGenesisAppliesDefaults(t *testing.T) {
	g := baseGenesis(testAccount(t, 1000, 100))
	path := writeGenesis(t, g)

	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BlockTimeSeconds != 5 {
		t.Errorf("expected default block_time_seconds 5, got %d", loaded.BlockTimeSeconds)
	}
	if loaded.MaxTxPerBlock != 500 {
		t.Errorf("expected default max_tx_per_block 500, got %d", loaded.MaxTxPerBlock)
	}
	if loaded.FinalityDepth != 100 {
		t.Errorf("expected default finality_depth 100, got %d", loaded.FinalityDepth)
	}
}

func TestLoadRejectsWrongProtocolVersion(t *testing.T) {
	g := baseGenesis(testAccount(t, 1000, 100))
	g.ProtocolVersion = ProtocolVersion + 1
	path := writeGenesis(t, g)
	if _, err := Load(path); err == nil {
		t.Fatal("expected mismatched protocol_version to be rejected")
	}
}

func TestLoadRejectsNoStake(t *testing.T) {
	g := baseGenesis(testAccount(t, 1000, 0))
	path := writeGenesis(t, g)
	if _, err := Load(path); err == nil {
		t.Fatal("expected genesis with zero total stake to be rejected")
	}
}

func TestLoadRejectsDuplicateAddress(t *testing.T) {
	a := testAccount(t, 1000, 100)
	dup := a
	dup.Balance = 1 // same address, different balance
	g := baseGenesis(a, dup)
	path := writeGenesis(t, g)
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate account address to be rejected")
	}
}

func TestLoadRejectsStakeBelowMinimum(t *testing.T) {
	g := baseGenesis(testAccount(t, 1000, 50))
	g.MinValidatorStake = 100
	path := writeGenesis(t, g)
	if _, err := Load(path); err == nil {
		t.Fatal("expected stake below min_validator_stake to be rejected")
	}
}

func TestLoadAllowsZeroStakeAccountRegardlessOfMinimum(t *testing.T) {
	validator := testAccount(t, 1000, 100)
	nonValidator := testAccount(t, 500, 0)
	g := baseGenesis(validator, nonValidator)
	g.MinValidatorStake = 100
	path := writeGenesis(t, g)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected zero-stake account to be allowed even with min_validator_stake set: %v", err)
	}
}

func TestLoadRejectsBalanceOverflowingMaxSupply(t *testing.T) {
	a := testAccount(t, types.MaxSupply, 100)
	b := testAccount(t, types.MaxSupply, 0)
	g := baseGenesis(a, b)
	path := writeGenesis(t, g)
	if _, err := Load(path); err == nil {
		t.Fatal("expected total balance exceeding max supply to be rejected")
	}
}
