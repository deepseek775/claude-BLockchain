package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// Block is a batch of transactions proposed and signed by the validator
// selected for this height by the proof-of-stake lottery (see internal/pos).
type Block struct {
	ChainID      string            `json:"chain_id"`
	Index        uint64            `json:"index"`
	Timestamp    int64             `json:"timestamp"`
	PrevHash     string            `json:"prev_hash"`
	Transactions []Transaction     `json:"transactions"`
	Reward       uint64            `json:"reward"` // sum of Transactions[*].Fee, paid to Validator
	Validator    string            `json:"validator"`
	ValidatorPub ed25519.PublicKey `json:"validator_pub"`
	Signature    []byte            `json:"signature,omitempty"`
	Hash         string            `json:"hash"`
}

var (
	ErrBadBlockSignature = errors.New("block: invalid validator signature")
	ErrBadBlockHash      = errors.New("block: hash does not match contents")
	ErrValidatorMismatch = errors.New("block: validator public key does not match address")
	ErrBadReward         = errors.New("block: reward does not match sum of transaction fees")
)

// signingBytes returns the deterministic pre-image that is hashed and
// signed. It intentionally excludes Signature and Hash.
func (b *Block) signingBytes() []byte {
	buf := make([]byte, 0, 128+64*len(b.Transactions))
	var idx, ts, reward [8]byte
	binary.BigEndian.PutUint64(idx[:], b.Index)
	binary.BigEndian.PutUint64(ts[:], uint64(b.Timestamp))
	binary.BigEndian.PutUint64(reward[:], b.Reward)
	writeStr := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	writeStr(b.ChainID)
	buf = append(buf, idx[:]...)
	buf = append(buf, ts[:]...)
	buf = append(buf, reward[:]...)
	writeStr(b.PrevHash)
	writeStr(b.Validator)
	buf = append(buf, b.ValidatorPub...)
	for i := range b.Transactions {
		h := b.Transactions[i].Hash()
		buf = append(buf, h[:]...)
	}
	return buf
}

// ComputeHash returns the hex-encoded SHA-256 hash of the block contents.
func (b *Block) ComputeHash() string {
	sum := sha256.Sum256(b.signingBytes())
	return hex.EncodeToString(sum[:])
}

// Sign fills in Hash and Signature using priv, which must belong to
// b.Validator.
func (b *Block) Sign(priv ed25519.PrivateKey) {
	b.Hash = b.ComputeHash()
	b.Signature = ed25519.Sign(priv, b.signingBytes())
}

// VerifyIntegrity checks that Hash and Signature are consistent with the
// block's contents and validator key, and that the block declares the
// expected network. It does not check consensus rules (validator
// eligibility, index/prevHash linkage, fee accounting) - see
// chain.validateBlockLocked / chain.applyBlockLocked.
func (b *Block) VerifyIntegrity(expectedChainID string) error {
	if b.ChainID != expectedChainID {
		return ErrWrongChain
	}
	if len(b.ValidatorPub) != ed25519.PublicKeySize {
		return ErrBadBlockSignature
	}
	if err := CheckAddress(b.Validator, b.ValidatorPub); err != nil {
		return ErrValidatorMismatch
	}
	if b.ComputeHash() != b.Hash {
		return ErrBadBlockHash
	}
	if !ed25519.Verify(b.ValidatorPub, b.signingBytes(), b.Signature) {
		return ErrBadBlockSignature
	}
	var wantReward uint64
	for i := range b.Transactions {
		sum, overflow := AddUint64(wantReward, b.Transactions[i].Fee)
		if overflow {
			return ErrAmountOverflow
		}
		wantReward = sum
	}
	if wantReward != b.Reward {
		return ErrBadReward
	}
	return nil
}
