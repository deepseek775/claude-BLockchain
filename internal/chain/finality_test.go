package chain

import (
	"crypto/ed25519"
	"testing"

	"claude-blockchain/internal/types"
)

// voteFor builds and signs a Vote from signer for the given block.
func voteFor(signer kp, block types.Block) types.Vote {
	v := types.Vote{ChainID: testChainID, BlockHash: block.Hash, Height: block.Index, Voter: signer.addr}
	v.Sign(signer.priv)
	return v
}

func TestAddVoteRequiresSupermajorityStake(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	cc := newKP(t)
	// a=500, b=300, cc=200, total=1000. 2/3 threshold is 666.67: a alone
	// (500) isn't enough, but a+b (800) is.
	g := testGenesis(t, account(a, 0, 500), account(b, 0, 300), account(cc, 0, 200))
	c, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	block, err := c.CreateBlock(nil, c.ExpectedValidator(), signerFor(t, c, a, b, cc))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}

	finalized, err := c.AddVote(voteFor(a, block))
	if err != nil {
		t.Fatalf("expected a's vote to be accepted, got %v", err)
	}
	if finalized {
		t.Fatal("expected a's vote alone (500/1000) not to finalize")
	}
	if c.FinalizedHeight() != 0 {
		t.Fatalf("expected finalized height still 0, got %d", c.FinalizedHeight())
	}

	finalized, err = c.AddVote(voteFor(b, block))
	if err != nil {
		t.Fatalf("expected b's vote to be accepted, got %v", err)
	}
	if !finalized {
		t.Fatal("expected a+b's votes (800/1000) to finalize")
	}
	if c.FinalizedHeight() != 1 {
		t.Fatalf("expected finalized height 1, got %d", c.FinalizedHeight())
	}
	if c.FinalizedHash() != block.Hash {
		t.Fatalf("expected finalized hash to match block, got %s", c.FinalizedHash())
	}
}

// signerFor picks whichever of the given validators the chain actually
// expects to propose next, so CreateBlock succeeds regardless of which one
// the stake-weighted lottery selects.
func signerFor(t *testing.T, c *Chain, candidates ...kp) ed25519.PrivateKey {
	t.Helper()
	expected := c.ExpectedValidator()
	for _, k := range candidates {
		if k.addr == expected {
			return k.priv
		}
	}
	t.Fatalf("no candidate matches expected validator %s", expected)
	return nil
}

func TestAddVoteRejectsNonValidator(t *testing.T) {
	a := newKP(t)
	outsider := newKP(t)
	g := testGenesis(t, account(a, 0, 100))
	c, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	block, err := c.CreateBlock(nil, a.addr, a.priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddVote(voteFor(outsider, block)); err == nil {
		t.Fatal("expected vote from a non-validator to be rejected")
	}
}

func TestAddVoteRejectsEquivocation(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 0, 500), account(b, 0, 500))
	c, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	block, err := c.CreateBlock(nil, c.ExpectedValidator(), signerFor(t, c, a, b))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}

	real := voteFor(a, block)
	if _, err := c.AddVote(real); err != nil {
		t.Fatalf("expected a's real vote to be accepted, got %v", err)
	}

	fake := types.Vote{ChainID: testChainID, BlockHash: "0000000000000000000000000000000000000000000000000000000000ff", Height: block.Index, Voter: a.addr}
	fake.Sign(a.priv)
	if _, err := c.AddVote(fake); err == nil {
		t.Fatal("expected a's conflicting second vote at the same height to be rejected")
	}

	// b's vote should still be able to push the real block to finality -
	// a's rejected equivocating vote must not have corrupted the tally.
	finalized, err := c.AddVote(voteFor(b, block))
	if err != nil {
		t.Fatalf("expected b's vote to be accepted, got %v", err)
	}
	if !finalized {
		t.Fatal("expected a (real vote) + b to finalize despite a's equivocation attempt")
	}
}

func TestAddVoteBuffersUntilBlockArrives(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 0, 500), account(b, 0, 500))
	c, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	block, err := c.CreateBlock(nil, c.ExpectedValidator(), signerFor(t, c, a, b))
	if err != nil {
		t.Fatal(err)
	}

	// Votes arrive before the block itself (a gossip race) - both should
	// be buffered rather than rejected.
	if finalized, err := c.AddVote(voteFor(a, block)); err != nil || finalized {
		t.Fatalf("expected a's early vote to be buffered (no error, not finalized), got finalized=%v err=%v", finalized, err)
	}
	if finalized, err := c.AddVote(voteFor(b, block)); err != nil || finalized {
		t.Fatalf("expected b's early vote to be buffered (no error, not finalized), got finalized=%v err=%v", finalized, err)
	}
	if c.FinalizedHeight() != 0 {
		t.Fatalf("expected finalized height still 0 before block arrives, got %d", c.FinalizedHeight())
	}

	// Now the block arrives - buffered votes should be replayed and
	// finalize it immediately.
	if err := c.AddBlock(block); err != nil {
		t.Fatal(err)
	}
	if c.FinalizedHeight() != 1 {
		t.Fatalf("expected buffered votes to finalize height 1 once the block arrived, got %d", c.FinalizedHeight())
	}
}

func TestReplaceChainRejectsReorgPastFinalizedHeight(t *testing.T) {
	a := newKP(t)
	b := newKP(t)
	g := testGenesis(t, account(a, 1000, 500), account(b, 1000, 500))
	g.FinalityDepth = 100 // deliberately generous, so only the finality VOTE (not depth) can be responsible for rejection

	c1, err := New(g, "")
	if err != nil {
		t.Fatal(err)
	}
	genesisBlock := c1.blocks[0]
	stakes := map[string]uint64{a.addr: 500, b.addr: 500}
	signers := map[string]kp{a.addr: a, b.addr: b}

	realHistory := buildChain(genesisBlock, signers, stakes, 1, 1)
	attackChain := buildChain(genesisBlock, signers, stakes, 2, 3) // longer, diverges at block 1

	if err := c1.AddBlock(realHistory[1]); err != nil {
		t.Fatal(err)
	}
	if realHistory[1].Hash == attackChain[1].Hash {
		t.Fatal("test setup bug: chains did not diverge at block 1")
	}

	if _, err := c1.AddVote(voteFor(a, realHistory[1])); err != nil {
		t.Fatalf("expected a's vote to be accepted, got %v", err)
	}
	finalized, err := c1.AddVote(voteFor(b, realHistory[1]))
	if err != nil {
		t.Fatalf("expected b's vote to be accepted, got %v", err)
	}
	if !finalized || c1.FinalizedHeight() != 1 {
		t.Fatalf("expected block 1 to be finalized, finalized=%v height=%d", finalized, c1.FinalizedHeight())
	}

	if err := c1.ReplaceChain(attackChain); err == nil {
		t.Fatal("expected reorg past a finalized block to be rejected even though it's within FinalityDepth")
	}
}
