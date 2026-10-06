package mempool

import (
	"crypto/ed25519"
	"testing"

	"claude-blockchain/internal/types"
)

func signedTx(t *testing.T, from string, priv ed25519.PrivateKey, amount, fee, nonce uint64) types.Transaction {
	t.Helper()
	tx := types.Transaction{ChainID: "c", From: from, To: "0xdead", Amount: amount, Fee: fee, Nonce: nonce}
	tx.Sign(priv)
	return tx
}

func TestAddDedup(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := New()
	tx := signedTx(t, types.AddressFromPubKey(pub), priv, 1, 0, 0)
	if ok, reason := m.Add(tx, 0, 1000); !ok {
		t.Fatalf("expected first add to succeed, got reason %q", reason)
	}
	if ok, _ := m.Add(tx, 0, 1000); ok {
		t.Fatal("expected duplicate add to fail")
	}
	if m.Len() != 1 {
		t.Fatalf("expected len 1, got %d", m.Len())
	}
}

func TestAddRejectsNonceGap(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := types.AddressFromPubKey(pub)
	m := New()
	// chain nonce is 0, nothing pending yet, so nonce 1 is not next.
	if ok, _ := m.Add(signedTx(t, addr, priv, 1, 0, 1), 0, 1000); ok {
		t.Fatal("expected a transaction skipping ahead of the pending sequence to be rejected")
	}
}

func TestAddQueuesSequentialNoncesFromSameSender(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := types.AddressFromPubKey(pub)
	m := New()
	// This is exactly the case that used to be impossible: a sender
	// queueing more than one not-yet-confirmed transaction at once.
	for i := uint64(0); i < 5; i++ {
		if ok, reason := m.Add(signedTx(t, addr, priv, 10, 1, i), 0, 1000); !ok {
			t.Fatalf("expected sequential nonce %d to be accepted, got reason %q", i, reason)
		}
	}
	if m.Len() != 5 {
		t.Fatalf("expected 5 queued transactions, got %d", m.Len())
	}
}

func TestAddRejectsPendingSpendExceedingBalance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := types.AddressFromPubKey(pub)
	m := New()
	// Balance is 100; two transactions of 60 each would total 120.
	if ok, _ := m.Add(signedTx(t, addr, priv, 60, 0, 0), 0, 100); !ok {
		t.Fatal("expected first transaction to be accepted")
	}
	if ok, reason := m.Add(signedTx(t, addr, priv, 60, 0, 1), 0, 100); ok {
		t.Fatalf("expected second transaction to be rejected for insufficient cumulative balance, got accepted (reason %q)", reason)
	}
}

func TestPerSenderLimit(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := types.AddressFromPubKey(pub)
	m := New()
	for i := uint64(0); i < maxPerSender; i++ {
		if ok, reason := m.Add(signedTx(t, addr, priv, 1, 0, i), 0, 1_000_000); !ok {
			t.Fatalf("expected add %d to succeed, got reason %q", i, reason)
		}
	}
	if ok, _ := m.Add(signedTx(t, addr, priv, 1, 0, maxPerSender), 0, 1_000_000); ok {
		t.Fatal("expected add beyond per-sender limit to fail")
	}
}

func TestTakeOrdersByFeeAcrossSendersButNonceWithinSender(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(nil)
	pubB, privB, _ := ed25519.GenerateKey(nil)
	addrA := types.AddressFromPubKey(pubA)
	addrB := types.AddressFromPubKey(pubB)
	m := New()

	// Sender A queues nonce 0 (low fee) then nonce 1 (high fee). Even
	// though nonce 1 pays more, it can never be selected before nonce 0 -
	// it isn't even a candidate until nonce 0 has been taken.
	m.Add(signedTx(t, addrA, privA, 1, 1, 0), 0, 1_000_000)
	m.Add(signedTx(t, addrA, privA, 1, 9, 1), 0, 1_000_000)
	// Sender B has a single mid-fee transaction.
	m.Add(signedTx(t, addrB, privB, 1, 5, 0), 0, 1_000_000)

	got := m.Take(3)
	if len(got) != 3 {
		t.Fatalf("expected 3 transactions, got %d", len(got))
	}
	// Round 1: A's head is nonce 0 (fee 1), B's head is nonce 0 (fee 5) -
	// B wins on fee alone, nothing stops it.
	if got[0].From != addrB {
		t.Fatalf("expected sender B (fee 5) first, got From=%s Fee=%d", got[0].From, got[0].Fee)
	}
	// Round 2: B is exhausted, so A's nonce 0 is the only candidate -
	// A's own nonce 1 (fee 9) is NOT yet eligible even though it would
	// outbid everything, because it isn't A's head yet.
	if got[1].From != addrA || got[1].Nonce != 0 {
		t.Fatalf("expected sender A's nonce 0 second, got From=%s Nonce=%d", got[1].From, got[1].Nonce)
	}
	// Round 3: A's nonce 0 was just picked, so A's nonce 1 becomes head
	// and is the only remaining candidate.
	if got[2].From != addrA || got[2].Nonce != 1 {
		t.Fatalf("expected sender A's nonce 1 last, got From=%s Nonce=%d", got[2].From, got[2].Nonce)
	}
}

func TestRemoveReleasesNonceAndBalanceSlots(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	addr := types.AddressFromPubKey(pub)
	m := New()
	tx0 := signedTx(t, addr, priv, 50, 0, 0)
	m.Add(tx0, 0, 100)
	// Confirm tx0 (as AddBlock+Remove would): chain nonce is now 1,
	// chain balance is now 50.
	m.Remove([]types.Transaction{tx0})
	if m.Len() != 0 {
		t.Fatalf("expected len 0 after remove, got %d", m.Len())
	}
	if ok, reason := m.Add(signedTx(t, addr, priv, 50, 0, 1), 1, 50); !ok {
		t.Fatalf("expected next transaction to be accepted against updated chain state, got reason %q", reason)
	}
}
