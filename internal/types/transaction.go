package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Transaction moves value from one account to another. Every field except
// Signature is covered by the signature, so nothing about a transaction can
// be altered in transit without invalidating it.
//
// ChainID binds a transaction to one specific network (the same idea as
// Ethereum's EIP-155): without it, a transaction valid on one network using
// this codebase would also be a valid, replayable transaction on any other
// network sharing the same address (e.g. a testnet and a mainnet run from
// the same binary). Fee is the amount paid to whichever validator proposes
// the block this transaction lands in; it both deters mempool-flooding spam
// and is a validator's actual incentive to participate.
type Transaction struct {
	ChainID   string            `json:"chain_id"`
	From      string            `json:"from"`
	To        string            `json:"to"`
	Amount    uint64            `json:"amount"`
	Fee       uint64            `json:"fee"`
	Nonce     uint64            `json:"nonce"`
	PublicKey ed25519.PublicKey `json:"public_key"`
	Signature []byte            `json:"signature"`
}

var (
	ErrInvalidSignature = errors.New("transaction: invalid signature")
	ErrZeroAmount       = errors.New("transaction: amount must be positive")
	ErrSelfTransfer     = errors.New("transaction: from and to must differ")
	ErrBadPublicKey     = errors.New("transaction: malformed public key")
	ErrWrongChain       = errors.New("transaction: chain_id does not match this network")
	ErrAmountOverflow   = errors.New("transaction: amount+fee overflows")
)

// signingBytes returns a deterministic, unambiguous encoding of every field
// that must be covered by the signature. Fields are length-prefixed so that,
// e.g., From="ab"+To="c" cannot collide with From="a"+To="bc".
func (tx *Transaction) signingBytes() []byte {
	buf := make([]byte, 0, len(tx.ChainID)+len(tx.From)+len(tx.To)+len(tx.PublicKey)+40)
	writeStr := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	writeStr(tx.ChainID)
	writeStr(tx.From)
	writeStr(tx.To)
	var amt, fee, nonce [8]byte
	binary.BigEndian.PutUint64(amt[:], tx.Amount)
	binary.BigEndian.PutUint64(fee[:], tx.Fee)
	binary.BigEndian.PutUint64(nonce[:], tx.Nonce)
	buf = append(buf, amt[:]...)
	buf = append(buf, fee[:]...)
	buf = append(buf, nonce[:]...)
	buf = append(buf, tx.PublicKey...)
	return buf
}

// Hash returns a content hash of the transaction, useful for dedup caches
// and block indexing.
func (tx *Transaction) Hash() [32]byte {
	return sha256.Sum256(append(tx.signingBytes(), tx.Signature...))
}

// Sign signs the transaction with priv and sets PublicKey/Signature. The
// caller must have already set ChainID (Sign does not fill it in, since a
// wallet-level bug that silently defaulted ChainID would be exactly the
// kind of gap this field exists to prevent).
func (tx *Transaction) Sign(priv ed25519.PrivateKey) {
	tx.PublicKey = priv.Public().(ed25519.PublicKey)
	tx.Signature = ed25519.Sign(priv, tx.signingBytes())
}

// Verify performs stateless validation: well-formed fields, chain binding,
// address/key consistency, and a valid signature. It does NOT check
// balances or nonces (that requires chain state, see
// chain.Chain.ValidateTransaction).
func (tx *Transaction) Verify(expectedChainID string) error {
	if tx.ChainID != expectedChainID {
		return ErrWrongChain
	}
	if tx.Amount == 0 {
		return ErrZeroAmount
	}
	if tx.From == tx.To {
		return ErrSelfTransfer
	}
	if _, overflow := AddUint64(tx.Amount, tx.Fee); overflow {
		return ErrAmountOverflow
	}
	if len(tx.PublicKey) != ed25519.PublicKeySize {
		return ErrBadPublicKey
	}
	if err := CheckAddress(tx.From, tx.PublicKey); err != nil {
		return err
	}
	if !ed25519.Verify(tx.PublicKey, tx.signingBytes(), tx.Signature) {
		return ErrInvalidSignature
	}
	return nil
}
