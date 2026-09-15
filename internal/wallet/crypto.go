package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

// Scrypt cost parameters. N=2^15 with r=8, p=1 takes roughly 100-400ms on
// typical hardware and ~32MB of memory - deliberately expensive enough to
// make brute-forcing a stolen wallet file costly, while staying fast
// enough not to be annoying on every node/tx invocation. Stored per-file
// (not hardcoded at load time) so a future, stronger default doesn't break
// wallets encrypted under an older one.
const (
	scryptN      = 1 << 15
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32 // AES-256
	saltLen      = 16
)

func encryptWalletFile(w *Wallet, passphrase string) (walletFile, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return walletFile{}, fmt.Errorf("generate salt: %w", err)
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return walletFile{}, fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return walletFile{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return walletFile{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return walletFile{}, fmt.Errorf("generate nonce: %w", err)
	}

	// Binding the address as additional authenticated data means an
	// encrypted private key blob can't be silently swapped into a
	// different wallet file (same passphrase, different claimed address)
	// without the AEAD tag failing to verify.
	ciphertext := gcm.Seal(nil, nonce, w.PrivateKey, []byte(w.Address))

	return walletFile{
		Version:    2,
		Address:    w.Address,
		PublicKey:  hex.EncodeToString(w.PublicKey),
		Encrypted:  true,
		Cipher:     "aes-256-gcm",
		KDF:        "scrypt",
		KDFSalt:    hex.EncodeToString(salt),
		ScryptN:    scryptN,
		ScryptR:    scryptR,
		ScryptP:    scryptP,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
	}, nil
}

func decryptWalletFile(wf walletFile, passphrase string) (ed25519.PrivateKey, error) {
	if wf.Cipher != "aes-256-gcm" || wf.KDF != "scrypt" {
		return nil, fmt.Errorf("wallet: unsupported cipher/kdf %q/%q", wf.Cipher, wf.KDF)
	}
	salt, err := hex.DecodeString(wf.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("wallet: malformed salt")
	}
	nonce, err := hex.DecodeString(wf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("wallet: malformed nonce")
	}
	ciphertext, err := hex.DecodeString(wf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("wallet: malformed ciphertext")
	}
	if wf.ScryptN <= 0 || wf.ScryptR <= 0 || wf.ScryptP <= 0 {
		return nil, fmt.Errorf("wallet: invalid scrypt parameters")
	}

	key, err := scrypt.Key([]byte(passphrase), salt, wf.ScryptN, wf.ScryptR, wf.ScryptP, scryptKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(wf.Address))
	if err != nil {
		return nil, fmt.Errorf("wallet: decryption failed (wrong passphrase or corrupted file)")
	}
	if len(plaintext) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("wallet: decrypted key has wrong size")
	}
	return ed25519.PrivateKey(plaintext), nil
}
