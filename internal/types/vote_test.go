package types

import (
	"crypto/ed25519"
	"testing"
)

func TestVoteSignVerifyRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := Vote{ChainID: "c", BlockHash: "deadbeef", Height: 3, Voter: AddressFromPubKey(pub)}
	v.Sign(priv)
	if err := v.Verify("c"); err != nil {
		t.Fatalf("expected valid vote, got %v", err)
	}
}

func TestVoteRejectsWrongChainID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := Vote{ChainID: "c", BlockHash: "deadbeef", Height: 3, Voter: AddressFromPubKey(pub)}
	v.Sign(priv)
	if err := v.Verify("other"); err != ErrWrongChain {
		t.Fatalf("expected ErrWrongChain, got %v", err)
	}
}

func TestVoteRejectsTamperedBlockHash(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := Vote{ChainID: "c", BlockHash: "deadbeef", Height: 3, Voter: AddressFromPubKey(pub)}
	v.Sign(priv)
	v.BlockHash = "tampered"
	if err := v.Verify("c"); err != ErrBadVoteSignature {
		t.Fatalf("expected ErrBadVoteSignature, got %v", err)
	}
}

func TestVoteRejectsSpoofedVoter(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	v := Vote{ChainID: "c", BlockHash: "deadbeef", Height: 3, Voter: AddressFromPubKey(otherPub)}
	v.Sign(priv) // signs with priv, but claims otherPub's address
	if err := v.Verify("c"); err != ErrVoterMismatch {
		t.Fatalf("expected ErrVoterMismatch, got %v", err)
	}
}
