// Package mempool holds pending, not-yet-included transactions.
package mempool

import (
	"sync"

	"claude-blockchain/internal/types"
)

const maxSize = 10_000

// Mempool is a concurrency-safe, deduplicated pool of pending transactions.
type Mempool struct {
	mu  sync.Mutex
	txs map[[32]byte]types.Transaction
}

func New() *Mempool {
	return &Mempool{txs: make(map[[32]byte]types.Transaction)}
}

// Add inserts tx if it is not already present and the pool has room.
// Returns true if the transaction was newly added.
func (m *Mempool) Add(tx types.Transaction) bool {
	h := tx.Hash()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.txs[h]; ok {
		return false
	}
	if len(m.txs) >= maxSize {
		return false
	}
	m.txs[h] = tx
	return true
}

// Has reports whether a transaction with this hash is already pooled.
func (m *Mempool) Has(h [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.txs[h]
	return ok
}

// Remove deletes a set of transactions (typically ones just included in a
// block) from the pool.
func (m *Mempool) Remove(txs []types.Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tx := range txs {
		delete(m.txs, tx.Hash())
	}
}

// Take returns up to n pending transactions for block proposal. It does not
// remove them; the caller removes them once the block is committed.
func (m *Mempool) Take(n int) []types.Transaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]types.Transaction, 0, n)
	for _, tx := range m.txs {
		if len(out) >= n {
			break
		}
		out = append(out, tx)
	}
	return out
}

// Len returns the number of pending transactions.
func (m *Mempool) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.txs)
}
