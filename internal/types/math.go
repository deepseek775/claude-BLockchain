package types

import "math"

// AddUint64 returns a+b and whether that addition overflowed a uint64.
// Every balance update in this codebase must go through this (or
// SubUint64) rather than the raw `+`/`-` operators: an unchecked uint64
// addition silently wraps around on overflow, which on a real ledger means
// an attacker could mint value out of thin air by engineering a transfer
// that overflows a recipient's balance back through zero.
func AddUint64(a, b uint64) (sum uint64, overflow bool) {
	sum = a + b
	return sum, sum < a
}

// SubUint64 returns a-b and whether b > a (i.e. the subtraction would have
// gone negative, which uint64 cannot represent and would instead wrap to a
// huge positive number).
func SubUint64(a, b uint64) (diff uint64, underflow bool) {
	if b > a {
		return 0, true
	}
	return a - b, false
}

// MaxSupply is the largest total value the ledger can ever represent
// without risking overflow in intermediate sums (e.g. total fees collected
// in one block, or a genesis balance sum). Genesis validation enforces
// that the sum of all starting balances stays under this.
const MaxSupply = math.MaxUint64 / 4
