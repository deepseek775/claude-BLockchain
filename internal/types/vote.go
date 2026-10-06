package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Vote is a validator's signed attestation that it has accepted a specific
// block at a specific height. Once votes covering more than 2/3 of total
// stake are collected for one block, that block (and everything before it)
// is treated as finalized - see chain.Chain.AddVote. This is what gives the
// chain BFT-style, near-instant finality instead of relying solely on
// depth-based reorg protection.
type Vote struct {
	ChainID   string            `json:"chain_id"`
	BlockHash string            `json:"block_hash"`
	Height    uint64            `json:"height"`
	Voter     string            `json:"voter"` // address of the attesting validator
	VoterPub  ed25519.PublicKey `json:"voter_pub"`
	Signature []byte            `json:"signature"`
}

var (
	ErrBadVoteSignature = errors.New("vote: invalid validator signature")
	ErrVoterMismatch    = errors.New("vote: public key does not match voter address")
)

// signingBytes returns the deterministic pre-image that is signed. It
// intentionally excludes Signature.
func (v *Vote) signingBytes() []byte {
	buf := make([]byte, 0, 64+len(v.ChainID)+len(v.BlockHash)+len(v.Voter)+len(v.VoterPub))
	var height [8]byte
	binary.BigEndian.PutUint64(height[:], v.Height)
	writeStr := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	writeStr(v.ChainID)
	writeStr(v.BlockHash)
	buf = append(buf, height[:]...)
	writeStr(v.Voter)
	buf = append(buf, v.VoterPub...)
	return buf
}

// Hash returns a content hash of the vote, used for gossip dedup.
func (v *Vote) Hash() [32]byte {
	return sha256.Sum256(append(v.signingBytes(), v.Signature...))
}

// Sign fills in VoterPub and Signature using priv, which must belong to
// v.Voter. The caller must have already set ChainID, BlockHash, Height and
// Voter.
func (v *Vote) Sign(priv ed25519.PrivateKey) {
	v.VoterPub = priv.Public().(ed25519.PublicKey)
	v.Signature = ed25519.Sign(priv, v.signingBytes())
}

// Verify performs stateless validation: well-formed fields, chain binding,
// address/key consistency, and a valid signature. It does NOT check whether
// Voter is actually a known validator with stake, or whether BlockHash
// matches a real block at Height - that requires chain state, see
// chain.Chain.AddVote.
func (v *Vote) Verify(expectedChainID string) error {
	if v.ChainID != expectedChainID {
		return ErrWrongChain
	}
	if len(v.VoterPub) != ed25519.PublicKeySize {
		return ErrBadPublicKey
	}
	if err := CheckAddress(v.Voter, v.VoterPub); err != nil {
		return ErrVoterMismatch
	}
	if !ed25519.Verify(v.VoterPub, v.signingBytes(), v.Signature) {
		return ErrBadVoteSignature
	}
	return nil
}
