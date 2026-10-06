package types

import (
	"crypto/ed25519"
	"testing"
)

func TestTransactionSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tx := Transaction{
		ChainID: "chain-a",
		From:    AddressFromPubKey(pub),
		To:      AddressFromPubKey(other),
		Amount:  100,
		Fee:     1,
		Nonce:   0,
	}
	tx.Sign(priv)
	if err := tx.Verify("chain-a"); err != nil {
		t.Fatalf("expected valid transaction to verify, got %v", err)
	}
}

func TestTransactionVerifyRejectsWrongChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	tx := Transaction{ChainID: "chain-a", From: AddressFromPubKey(pub), To: AddressFromPubKey(other), Amount: 1}
	tx.Sign(priv)
	if err := tx.Verify("chain-b"); err != ErrWrongChain {
		t.Fatalf("expected ErrWrongChain, got %v", err)
	}
}

func TestTransactionVerifyRejectsTamperedAmount(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	tx := Transaction{ChainID: "chain-a", From: AddressFromPubKey(pub), To: AddressFromPubKey(other), Amount: 1}
	tx.Sign(priv)
	tx.Amount = 1_000_000
	if err := tx.Verify("chain-a"); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestTransactionVerifyRejectsAmountFeeOverflow(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	tx := Transaction{
		ChainID: "chain-a",
		From:    AddressFromPubKey(pub),
		To:      AddressFromPubKey(other),
		Amount:  1<<64 - 1,
		Fee:     1,
	}
	tx.Sign(priv)
	if err := tx.Verify("chain-a"); err != ErrAmountOverflow {
		t.Fatalf("expected ErrAmountOverflow, got %v", err)
	}
}

func TestTransactionVerifyRejectsSpoofedFrom(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	victim, _, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	tx := Transaction{
		ChainID:   "chain-a",
		From:      AddressFromPubKey(victim), // claims to be from victim...
		To:        AddressFromPubKey(other),
		Amount:    1,
		PublicKey: pub, // ...but is actually signed by an unrelated key
	}
	tx.Signature = ed25519.Sign(priv, tx.signingBytes())
	if err := tx.Verify("chain-a"); err == nil {
		t.Fatal("expected spoofed From address to be rejected")
	}
}
