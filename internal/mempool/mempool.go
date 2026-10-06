// Package mempool holds pending, not-yet-included transactions.
package mempool

import (
	"sort"
	"sync"

	"claude-blockchain/internal/types"
)

// maxSize bounds total pooled transactions; maxPerSender bounds how many
// of them may come from a single account. Without the latter, one account
// (even paying the minimum fee) could occupy the entire mempool and crowd
// out everyone else - a cheap denial-of-service against a payment network,
// since mempool space is otherwise first-come-first-served.
const (
	maxSize      = 10_000
	maxPerSender = 64
)

// Mempool is a concurrency-safe, deduplicated pool of pending transactions.
//
// Admission is nonce- and balance-aware across a sender's *own* pending
// transactions, not just against the last confirmed chain state: without
// this, a sender could never have more than one transaction in flight at
// once (every transaction past the first would be rejected as "wrong
// nonce" until the first confirms), which is not how real payment
// networks behave. pendingNonceBase/pendingSpend track, per sender, the
// contiguous nonce run and cumulative amount+fee currently queued, so a
// second, third, ... transaction is accepted as long as it continues that
// sender's nonce sequence and the sender's confirmed balance can cover
// everything already queued plus the new one.
type Mempool struct {
	mu           sync.Mutex
	txs          map[[32]byte]types.Transaction
	bySender     map[string]int
	pendingSpend map[string]uint64 // sum of (amount+fee) currently pooled per sender
}

func New() *Mempool {
	return &Mempool{
		txs:          make(map[[32]byte]types.Transaction),
		bySender:     make(map[string]int),
		pendingSpend: make(map[string]uint64),
	}
}

// Add inserts tx if: it's not already present, the pool and the sender's
// per-sender slot both have room, tx.Nonce is exactly the next nonce after
// chainNonce and whatever's already queued for this sender, and the
// sender's chainBalance can cover chainBalance's already-queued spend plus
// this transaction's amount+fee. chainNonce/chainBalance are the sender's
// last *confirmed* values, supplied by the caller (chain.Chain) so this
// check happens atomically with the pool mutation instead of racing a
// separate pre-check against those values.
//
// Returns (accepted, reason) so callers can report a specific rejection
// instead of a bare false.
func (m *Mempool) Add(tx types.Transaction, chainNonce, chainBalance uint64) (bool, string) {
	h := tx.Hash()
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.txs[h]; ok {
		return false, "already in mempool"
	}
	if len(m.txs) >= maxSize {
		return false, "mempool full"
	}
	if m.bySender[tx.From] >= maxPerSender {
		return false, "sender has too many pending transactions"
	}

	expectedNonce := chainNonce + uint64(m.bySender[tx.From])
	if tx.Nonce != expectedNonce {
		return false, "nonce does not continue this sender's pending sequence"
	}

	spend, overflow := types.AddUint64(tx.Amount, tx.Fee)
	if overflow {
		return false, "amount+fee overflows"
	}
	totalPending, overflow := types.AddUint64(m.pendingSpend[tx.From], spend)
	if overflow || totalPending > chainBalance {
		return false, "insufficient balance to cover already-pending transactions plus this one"
	}

	m.txs[h] = tx
	m.bySender[tx.From]++
	m.pendingSpend[tx.From] = totalPending
	return true, ""
}

// Has reports whether a transaction with this hash is already pooled.
func (m *Mempool) Has(h [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.txs[h]
	return ok
}

// Remove deletes a set of transactions (typically ones just included in a
// block) from the pool and releases their reserved nonce/balance slots.
func (m *Mempool) Remove(txs []types.Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tx := range txs {
		h := tx.Hash()
		if _, ok := m.txs[h]; !ok {
			continue
		}
		delete(m.txs, h)
		m.bySender[tx.From]--
		if m.bySender[tx.From] <= 0 {
			delete(m.bySender, tx.From)
			delete(m.pendingSpend, tx.From)
			continue
		}
		spend, _ := types.AddUint64(tx.Amount, tx.Fee)
		remaining, underflow := types.SubUint64(m.pendingSpend[tx.From], spend)
		if underflow {
			remaining = 0
		}
		m.pendingSpend[tx.From] = remaining
	}
}

// Take returns up to n pending transactions for block proposal. Ordering
// respects two rules at once: a sender's own transactions always come out
// in nonce order (never a later nonce before an earlier one - the whole
// point of tracking pending nonce sequences above would otherwise be
// undone by the block builder), and, subject to that, higher-fee
// transactions are preferred - at each step, among every sender's next
// not-yet-picked transaction, the highest fee wins. This is the standard
// "nonce-ordered per account, fee-ordered across accounts" mempool
// selection real fee-market payment networks use.
func (m *Mempool) Take(n int) []types.Transaction {
	m.mu.Lock()
	bySenderList := make(map[string][]types.Transaction)
	for _, tx := range m.txs {
		bySenderList[tx.From] = append(bySenderList[tx.From], tx)
	}
	m.mu.Unlock()

	senders := make([]string, 0, len(bySenderList))
	for s, list := range bySenderList {
		sort.Slice(list, func(i, j int) bool { return list[i].Nonce < list[j].Nonce })
		bySenderList[s] = list
		senders = append(senders, s)
	}
	pos := make(map[string]int, len(senders))

	out := make([]types.Transaction, 0, n)
	for len(out) < n {
		bestIdx := -1
		var best types.Transaction
		for i, s := range senders {
			p := pos[s]
			list := bySenderList[s]
			if p >= len(list) {
				continue
			}
			cand := list[p]
			if bestIdx == -1 || feeThenHashLess(best, cand) {
				bestIdx = i
				best = cand
			}
		}
		if bestIdx == -1 {
			break
		}
		out = append(out, best)
		pos[senders[bestIdx]]++
	}
	return out
}

// feeThenHashLess reports whether b should be preferred over a: higher fee
// first, then a deterministic hash tie-break so equal-fee candidates don't
// reorder nondeterministically between calls.
func feeThenHashLess(a, b types.Transaction) bool {
	if a.Fee != b.Fee {
		return b.Fee > a.Fee
	}
	ha, hb := a.Hash(), b.Hash()
	return string(hb[:]) < string(ha[:])
}

// Len returns the number of pending transactions.
func (m *Mempool) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.txs)
}
