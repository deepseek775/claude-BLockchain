package chain

import (
	"crypto/ed25519"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"claude-blockchain/internal/genesis"
	"claude-blockchain/internal/pos"
	"claude-blockchain/internal/types"
)

const testChainID = "test-chain"

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
		ProtocolVersion:  genesis.ProtocolVersion,
		ChainID:          testChainID,
		Timestamp:        time.Now().Unix(),
		BlockTimeSeconds: 1,
		MaxTxPerBlock:    10,
		MaxBlockBytes:    1 << 20,
		FinalityDepth:    5,
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

// newTx builds and signs a transaction bound to testChainID, the shared
// fixture chain ID every test genesis above uses.
func newTx(from kp, to string, amount, fee, nonce uint64) types.Transaction {
	tx := types.Transaction{
		ChainID: testChainID,
		From:    from.addr,
		To:      to,
		Amount:  amount,
		Fee:     fee,
		Nonce:   nonce,
	}
	tx.Sign(from.priv)
	return tx
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

func TestAddBlockAppliesTransactionsAndPaysProposerFee(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100), account(b, 0, 0)), "")
	if err != nil {
		t.Fatal(err)
	}

	tx := newTx(a, b.addr, 250, 5, 0)

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
	if block.Reward != 5 {
		t.Fatalf("expected block reward 5, got %d", block.Reward)
	}
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}

	// a started with 1000, spent 250+5 (amount+fee), and gets the fee back
	// as proposer reward since a is also the block's validator here.
	if got := c.GetBalance(a.addr); got != 1000-255+5 {
		t.Fatalf("sender/proposer balance: expected %d, got %d", 1000-255+5, got)
	}
	if got := c.GetBalance(b.addr); got != 250 {
		t.Fatalf("recipient balance: expected 250, got %d", got)
	}
	if got := c.GetNonce(a.addr); got != 1 {
		t.Fatalf("sender nonce: expected 1, got %d", got)
	}
}

func TestValidateTransactionRejectsWrongChainID(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100)), "")
	if err != nil {
		t.Fatal(err)
	}
	tx := types.Transaction{ChainID: "some-other-chain", From: a.addr, To: b.addr, Amount: 10, Nonce: 0}
	tx.Sign(a.priv)
	if err := c.ValidateTransaction(tx); err == nil {
		t.Fatal("expected transaction with wrong chain_id to be rejected")
	}
}

func TestValidateTransactionRejectsFeeBelowMinimum(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 1000, 100))
	g.MinFee = 10
	c, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	tx := newTx(a, b.addr, 100, 5, 0) // fee below the 10 minimum
	if err := c.ValidateTransaction(tx); err == nil {
		t.Fatal("expected transaction with fee below minimum to be rejected")
	}
}

func TestCreateBlockDropsTransactionThatWouldOverflowRecipient(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100), account(b, math.MaxUint64-100, 0)), "")
	if err != nil {
		t.Fatal(err)
	}
	tx := newTx(a, b.addr, 200, 0, 0) // would push b's balance past MaxUint64
	block, err := c.CreateBlock([]types.Transaction{tx}, a.addr, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	if len(block.Transactions) != 0 {
		t.Fatalf("expected overflow-risking tx to be dropped, got %d included", len(block.Transactions))
	}
}

func TestAddBlockRejectsBadSignature(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	c, err := New(testGenesis(t, account(a, 1000, 100)), "")
	if err != nil {
		t.Fatal(err)
	}

	tx := newTx(a, b.addr, 100, 0, 0)
	tx.Amount = 999 // tamper after signing

	block, _ := c.CreateBlock(nil, a.addr, a.priv)
	block.Transactions = []types.Transaction{tx}
	block.Reward = 0
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

	tx1 := newTx(a, b.addr, 60, 0, 0)
	tx2 := newTx(a, cc.addr, 60, 0, 0) // same nonce, would overspend

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

// signManualBlock builds and signs a block directly (bypassing
// Chain.CreateBlock) so tests can control its timestamp precisely -
// needed to force two independently-built chains to diverge at an exact,
// predictable height instead of relying on wall-clock timing.
func signManualBlock(prevHash string, index uint64, timestamp int64, signer kp) types.Block {
	b := types.Block{
		ChainID:      testChainID,
		Index:        index,
		Timestamp:    timestamp,
		PrevHash:     prevHash,
		Validator:    signer.addr,
		ValidatorPub: signer.pub,
	}
	b.Sign(signer.priv)
	return b
}

// buildChain extends genesisBlock for n empty blocks, each proposed by
// whichever validator the PoS lottery selects, with timestamps
// genesisBlock.Timestamp + tsStep*i - a distinct tsStep between two calls
// sharing the same genesis guarantees the resulting chains diverge at
// block 1 even when they happen to pick the same validator.
func buildChain(genesisBlock types.Block, signers map[string]kp, stakes map[string]uint64, n int, tsStep int64) []types.Block {
	blocks := []types.Block{genesisBlock}
	last := genesisBlock
	for i := 1; i <= n; i++ {
		validatorAddr := pos.SelectValidator(last.Hash, uint64(i), stakes)
		b := signManualBlock(last.Hash, uint64(i), genesisBlock.Timestamp+tsStep*int64(i), signers[validatorAddr])
		blocks = append(blocks, b)
		last = b
	}
	return blocks
}

func TestReplaceChainRejectsDeepReorgPastFinality(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 1000, 500), account(b, 1000, 500))
	g.FinalityDepth = 2

	c1, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	genesisBlock := c1.blocks[0]
	stakes := map[string]uint64{a.addr: 500, b.addr: 500}
	signers := map[string]kp{a.addr: a, b.addr: b}

	// Two independently-built chains sharing only genesis - the classic
	// PoS "long-range attack" shape. Distinct tsStep values (1 vs 3)
	// guarantee they diverge starting at block 1.
	realHistory := buildChain(genesisBlock, signers, stakes, 4, 1)
	attackChain := buildChain(genesisBlock, signers, stakes, 5, 3) // longer, but shares nothing past genesis

	for _, blk := range realHistory[1:] {
		if err := c1.AddBlock(blk); err != nil {
			t.Fatal(err)
		}
	}
	// Sanity check the two histories actually diverge where the test
	// assumes they do, so a future change to buildChain can't silently
	// turn this into a no-op test.
	if realHistory[1].Hash == attackChain[1].Hash {
		t.Fatal("test setup bug: chains did not diverge at block 1")
	}

	if err := c1.ReplaceChain(attackChain); err == nil {
		t.Fatal("expected deep reorg past finality depth to be rejected")
	}
}

func TestReplaceChainAcceptsExtensionWithinFinality(t *testing.T) {
	a := newKP(t)
	g := testGenesis(t, account(a, 1000, 500))
	g.FinalityDepth = 2

	c1, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		block, err := c2.CreateBlock(nil, a.addr, a.priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := c2.AddBlock(block); err != nil {
			t.Fatal(err)
		}
	}

	if err := c1.ReplaceChain(c2.Blocks()); err != nil {
		t.Fatalf("expected pure extension (no reorg) to be accepted: %v", err)
	}
	if c1.Height() != 3 {
		t.Fatalf("expected height 3 after sync, got %d", c1.Height())
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
	tx := newTx(a, b.addr, 300, 0, 0)
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
