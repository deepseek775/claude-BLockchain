// Package pos implements a small deterministic proof-of-stake validator
// lottery: every node, given the same previous block hash, height, and
// stake table, computes the same next proposer without any extra network
// round-trip.
//
// This is intentionally simple ("small but secure" per the project brief)
// rather than a full VRF-based lottery: the randomness source is the
// previous block's hash, which is unpredictable before that block is
// signed but, once known, is public - so a validator knows one slot ahead
// of time whether it is about to propose. For a small demo/education chain
// this trade-off is acceptable and documented; it is not suitable for a
// high-value production chain, where a VRF (e.g. draft-irtf-cfrg-vrf)
// should replace SelectValidator's randomness source.
package pos

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"
)

// SelectValidator deterministically picks the next block proposer from
// stakes (address -> stake amount), weighted by stake, seeded by prevHash
// and height. Validators with zero stake never get selected. Returns ""
// if no validator has positive stake.
func SelectValidator(prevHash string, height uint64, stakes map[string]uint64) string {
	if len(stakes) == 0 {
		return ""
	}

	// Sort addresses for a canonical iteration order; map iteration order
	// in Go is randomized, and without a fixed order every node could
	// derive a different winner from the same stake table.
	addrs := make([]string, 0, len(stakes))
	var total uint64
	for a, s := range stakes {
		if s == 0 {
			continue
		}
		addrs = append(addrs, a)
		total += s
	}
	if total == 0 {
		return ""
	}
	sort.Strings(addrs)

	seed := seedFor(prevHash, height)
	r := new(big.Int).Mod(seed, new(big.Int).SetUint64(total)).Uint64()

	var cumulative uint64
	for _, a := range addrs {
		cumulative += stakes[a]
		if r < cumulative {
			return a
		}
	}
	// Unreachable if total was computed correctly, but fail safe to the
	// last validator rather than returning "".
	return addrs[len(addrs)-1]
}

func seedFor(prevHash string, height uint64) *big.Int {
	h := sha256.New()
	h.Write([]byte(prevHash))
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], height)
	h.Write(hb[:])
	sum := h.Sum(nil)
	return new(big.Int).SetBytes(sum)
}
