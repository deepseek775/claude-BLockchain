package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"claude-blockchain/internal/genesis"
	"claude-blockchain/internal/types"
)

type kp struct {
	addr string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKP(t *testing.T) kp {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return kp{addr: types.AddressFromPubKey(pub), pub: pub, priv: priv}
}

func testGenesis(t *testing.T, accounts ...genesis.Account) *genesis.Genesis {
	t.Helper()
	return &genesis.Genesis{
		ChainID:          "test-chain",
		Timestamp:        time.Now().Unix(),
		BlockTimeSeconds: 1,
		MaxTxPerBlock:    10,
		Accounts:         accounts,
	}
}

func account(k kp, balance, stake uint64) genesis.Account {
	return genesis.Account{
		Address:   k.addr,
		PublicKey: hex.EncodeToString(k.pub),
		Balance:   balance,
		Stake:     stake,
	}
}

func TestGenesisChainStartsAtZero(t *testing.T) {
	a := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100)), "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Height() != 0 {
		t.Fatalf("expected height 0, got %d", c.Height())
	}
	if c.GetBalance(a.addr) != 1000 {
		t.Fatalf("expected balance 1000, got %d", c.GetBalance(a.addr))
	}
}

func TestAddBlockAppliesTransactions(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100), account(b, 0, 0)), "")
	if err != nil {
		t.Fatal(err)
	}

	tx := types.Transaction{From: a.addr, To: b.addr, Amount: 250, Nonce: 0}
	tx.Sign(a.priv)

	validator := c.ExpectedValidator()
	if validator != a.addr {
		t.Fatalf("expected validator %s (only staker), got %s", a.addr, validator)
	}

	block, err := c.CreateBlock([]types.Transaction{tx}, a.addr, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Transactions) != 1 {
		t.Fatalf("expected 1 tx in block, got %d", len(block.Transactions))
	}
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}

	if got := c.GetBalance(a.addr); got != 750 {
		t.Fatalf("sender balance: expected 750, got %d", got)
	}
	if got := c.GetBalance(b.addr); got != 250 {
		t.Fatalf("recipient balance: expected 250, got %d", got)
	}
	if got := c.GetNonce(a.addr); got != 1 {
		t.Fatalf("sender nonce: expected 1, got %d", got)
	}
}

func TestAddBlockRejectsBadSignature(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100)), "")
	if err != nil {
		t.Fatal(err)
	}

	tx := types.Transaction{From: a.addr, To: b.addr, Amount: 100, Nonce: 0}
	tx.Sign(a.priv)
	tx.Amount = 999 // tamper after signing

	block, _ := c.CreateBlock(nil, a.addr, a.priv)
	block.Transactions = []types.Transaction{tx}
	block.Sign(a.priv)

	if err := c.AddBlock(block); err == nil {
		t.Fatal("expected tampered transaction to be rejected")
	}
}

func TestAddBlockRejectsDoubleSpend(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	cc := newKP(t)
	c, err := New(testGenesis(t, account(a, 100, 100), account(b, 0, 0), account(cc, 0, 0)), "")
	if err != nil {
		t.Fatal(err)
	}

	tx1 := types.Transaction{From: a.addr, To: b.addr, Amount: 60, Nonce: 0}
	tx1.Sign(a.priv)
	tx2 := types.Transaction{From: a.addr, To: cc.addr, Amount: 60, Nonce: 0} // same nonce, would overspend
	tx2.Sign(a.priv)

	block, _ := c.CreateBlock([]types.Transaction{tx1, tx2}, a.addr, a.priv)
	// CreateBlock should have dropped the second (invalid at that point in
	// the batch) transaction rather than including both.
	if len(block.Transactions) != 1 {
		t.Fatalf("expected CreateBlock to drop the conflicting tx, got %d included", len(block.Transactions))
	}

	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}
	if c.GetBalance(a.addr) != 40 {
		t.Fatalf("expected balance 40 after single spend, got %d", c.GetBalance(a.addr))
	}
}

func TestAddBlockRejectsWrongValidator(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100), account(b, 0, 0)), "")
	if err != nil {
		t.Fatal(err)
	}
	// b has zero stake, so it must never be a valid proposer.
	block, err := c.CreateBlock(nil, b.addr, b.priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddBlock(block); err == nil {
		t.Fatal("expected block from unstaked validator to be rejected")
	}
}

func TestReplaceChainRejectsForeignGenesis(t *testing.T) {
	a := newKP(t)
	c1, err := New(testGenesis(t, account(a, 1000, 100)), "")
	if err != nil {
		t.Fatal(err)
	}
	other := newKP(t)
	g2 := testGenesis(t, account(other, 1000, 100))
	g2.Timestamp = c1.blocks[0].Timestamp + 1 // force a different genesis hash
	c2, err := New(g2, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.ReplaceChain(c2.Blocks()); err == nil {
		t.Fatal("expected replace with foreign genesis to be rejected")
	}
}

func TestPersistenceReplaysAfterRestart(t *testing.T) {
	dir := t.TempDir()
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 1000, 100), account(b, 0, 0))

	c, err := New(g, dir+"/blocks.log")
	if err != nil {
		t.Fatal(err)
	}
	tx := types.Transaction{From: a.addr, To: b.addr, Amount: 300, Nonce: 0}
	tx.Sign(a.priv)
	block, _ := c.CreateBlock([]types.Transaction{tx}, a.addr, a.priv)
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}
	c.Close()

	c2, err := New(g, dir+"/blocks.log")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.Height() != 1 {
		t.Fatalf("expected replayed height 1, got %d", c2.Height())
	}
	if got := c2.GetBalance(b.addr); got != 300 {
		t.Fatalf("expected replayed balance 300, got %d", got)
	}
}
