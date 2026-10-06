package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// AddressFromPubKey derives a short account address from an ed25519 public
// key: hex(sha256(pubkey))[:40], prefixed with "0x". Using a hash of the key
// (rather than the raw key) keeps addresses short and means an attacker
// cannot forge a transaction "from" an address without first breaking
// SHA-256 preimage resistance in addition to Ed25519.
func AddressFromPubKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "0x" + hex.EncodeToString(sum[:])[:40]
}

var ErrAddressMismatch = errors.New("public key does not match address")

// CheckAddress verifies that pub is indeed the key that produced addr.
func CheckAddress(addr string, pub ed25519.PublicKey) error {
	if AddressFromPubKey(pub) != addr {
		return ErrAddressMismatch
	}
	return nil
}
