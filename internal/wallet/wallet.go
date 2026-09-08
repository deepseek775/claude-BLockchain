// Package wallet handles ed25519 keypair generation and on-disk storage for
// node/user identities.
package wallet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"claude-blockchain/internal/types"
)

// Wallet holds an account keypair in memory.
type Wallet struct {
	Address    string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// walletFile is the on-disk JSON shape. Keys are hex-encoded (matching
// genesis.json's convention) rather than Go's default base64 []byte
// encoding, so a key can be copy-pasted between a wallet file and a
// genesis file without re-encoding.
type walletFile struct {
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

// New generates a fresh keypair.
func New() (*Wallet, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return &Wallet{
		Address:    types.AddressFromPubKey(pub),
		PublicKey:  pub,
		PrivateKey: priv,
	}, nil
}

// Save writes the wallet to path as JSON with owner-only permissions, since
// the file contains a private key.
func (w *Wallet) Save(path string) error {
	data, err := json.MarshalIndent(walletFile{
		Address:    w.Address,
		PublicKey:  hex.EncodeToString(w.PublicKey),
		PrivateKey: hex.EncodeToString(w.PrivateKey),
	}, "", "  ")
	if err != nil {
		return err
	}
	// 0600: only the owner can read/write. Private key material must never
	// be group- or world-readable.
	return os.WriteFile(path, data, 0o600)
}

// Load reads a wallet previously written by Save and verifies internal
// consistency (address matches public key, public key matches private key).
func Load(path string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wf walletFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse wallet: %w", err)
	}

	priv, err := hex.DecodeString(wf.PrivateKey)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("wallet: malformed private key")
	}
	pub, err := hex.DecodeString(wf.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wallet: malformed public key")
	}

	w := &Wallet{
		Address:    wf.Address,
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: ed25519.PrivateKey(priv),
	}
	if !w.PrivateKey.Public().(ed25519.PublicKey).Equal(w.PublicKey) {
		return nil, fmt.Errorf("wallet: public/private key mismatch")
	}
	if err := types.CheckAddress(w.Address, w.PublicKey); err != nil {
		return nil, fmt.Errorf("wallet: %w", err)
	}
	return w, nil
}
