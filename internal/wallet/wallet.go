// Package wallet handles ed25519 keypair generation and on-disk storage for
// node/user identities, including passphrase-encrypted storage so a
// private key is never required to sit in plaintext on disk.
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
//
// Version 1 files store PrivateKey in plaintext hex (Encrypted absent/
// false) and are still readable for backward compatibility, but Save now
// always encrypts. A plaintext wallet on a shared or backed-up filesystem
// is a bearer instrument for whatever it holds - encrypting it at rest is
// the single highest-value change for handling real value with this code.
type walletFile struct {
	Version    int    `json:"version"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key"`
	Encrypted  bool   `json:"encrypted"`
	PrivateKey string `json:"private_key,omitempty"` // only set when !Encrypted

	// Present only when Encrypted is true.
	Cipher     string `json:"cipher,omitempty"`   // "aes-256-gcm"
	KDF        string `json:"kdf,omitempty"`      // "scrypt"
	KDFSalt    string `json:"kdf_salt,omitempty"` // hex
	ScryptN    int    `json:"scrypt_n,omitempty"`
	ScryptR    int    `json:"scrypt_r,omitempty"`
	ScryptP    int    `json:"scrypt_p,omitempty"`
	Nonce      string `json:"nonce,omitempty"`      // hex
	Ciphertext string `json:"ciphertext,omitempty"` // hex
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

// Save writes the wallet to path, encrypted with passphrase, with
// owner-only file permissions. An empty passphrase is refused: use
// SaveInsecurePlaintext explicitly (and only for throwaway/test wallets)
// if you really want an unencrypted file.
func (w *Wallet) Save(path, passphrase string) error {
	if passphrase == "" {
		return fmt.Errorf("wallet: refusing to save with an empty passphrase (use SaveInsecurePlaintext for a throwaway/test wallet)")
	}
	wf, err := encryptWalletFile(w, passphrase)
	if err != nil {
		return err
	}
	return writeWalletFile(path, wf)
}

// SaveInsecurePlaintext writes the wallet with its private key in
// plaintext. Only ever appropriate for disposable local test wallets -
// anything holding real value must use Save.
func (w *Wallet) SaveInsecurePlaintext(path string) error {
	wf := walletFile{
		Version:    1,
		Address:    w.Address,
		PublicKey:  hex.EncodeToString(w.PublicKey),
		Encrypted:  false,
		PrivateKey: hex.EncodeToString(w.PrivateKey),
	}
	return writeWalletFile(path, wf)
}

func writeWalletFile(path string, wf walletFile) error {
	data, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return err
	}
	// 0600: only the owner can read/write. Key material - encrypted or
	// not - must never be group- or world-readable.
	return os.WriteFile(path, data, 0o600)
}

// IsEncrypted reports whether the wallet file at path is passphrase
// encrypted, without needing a passphrase to check.
func IsEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var wf walletFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return false, fmt.Errorf("parse wallet: %w", err)
	}
	return wf.Encrypted, nil
}

// Load reads a wallet previously written by Save/SaveInsecurePlaintext. If
// the file is encrypted, passphrase must be correct (an empty passphrase
// against an encrypted file always fails). Load also verifies internal
// consistency: address matches public key, public key matches private key.
func Load(path, passphrase string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wf walletFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse wallet: %w", err)
	}

	var priv ed25519.PrivateKey
	if wf.Encrypted {
		if passphrase == "" {
			return nil, fmt.Errorf("wallet: file is encrypted but no passphrase was provided")
		}
		priv, err = decryptWalletFile(wf, passphrase)
		if err != nil {
			return nil, err
		}
	} else {
		b, err := hex.DecodeString(wf.PrivateKey)
		if err != nil || len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("wallet: malformed private key")
		}
		priv = ed25519.PrivateKey(b)
	}

	pub, err := hex.DecodeString(wf.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wallet: malformed public key")
	}

	w := &Wallet{
		Address:    wf.Address,
		PublicKey:  ed25519.PublicKey(pub),
		PrivateKey: priv,
	}
	if !w.PrivateKey.Public().(ed25519.PublicKey).Equal(w.PublicKey) {
		return nil, fmt.Errorf("wallet: public/private key mismatch (wrong passphrase?)")
	}
	if err := types.CheckAddress(w.Address, w.PublicKey); err != nil {
		return nil, fmt.Errorf("wallet: %w", err)
	}
	return w, nil
}
