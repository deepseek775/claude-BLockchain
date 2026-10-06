package chain

import (
	"fmt"
	"math/big"

	"claude-blockchain/internal/types"
)

// maxPendingVotes bounds how many not-yet-applicable votes (for a height we
// haven't reached yet) this node buffers at once. Votes typically arrive
// shortly after the block they attest to (gossip races are the common
// case, not the norm), so a small bound is enough; anything beyond it is
// dropped rather than risk unbounded memory from a peer flooding
// future-height votes.
const maxPendingVotes = 4096

// AddVote validates and records a validator's commit vote for a block. If
// the referenced block isn't in our chain yet, the vote is buffered
// (bounded by maxPendingVotes) and automatically reprocessed once/if that
// block is added. Returns whether this vote newly finalized a block.
//
// A block is finalized once votes from validators together holding more
// than 2/3 of total stake have been collected for it. This is what gives
// the chain BFT-style, near-instant finality: unlike the depth-based
// heuristic (FinalityDepth), which only makes a reorg past a certain age
// increasingly unlikely to be accepted, a finalized block can never be
// reorged at all - ReplaceChain refuses any candidate that would rewrite
// it (see sync.go).
//
// This is a simplified, single-round attestation scheme, not full
// Tendermint-style BFT: there is no separate prevote/precommit phase, no
// view-change/timeout handling for a stalled round, and no slashing for
// equivocation (a validator signing conflicting votes at the same height
// is detected and its second vote rejected, but not punished). It relies
// on the same fixed, genesis-defined validator set the rest of this chain
// uses - there is no dynamic validator rotation to reason about. See
// README's Production Readiness section for the full list of documented
// simplifications.
func (c *Chain) AddVote(v types.Vote) (finalizedNow bool, err error) {
	if err := v.Verify(c.chainID); err != nil {
		return false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.addVoteLocked(v)
}

// addVoteLocked assumes v has already passed stateless Verify. Caller must
// hold c.mu (write lock).
func (c *Chain) addVoteLocked(v types.Vote) (bool, error) {
	stake, ok := c.stakes[v.Voter]
	if !ok || stake == 0 {
		return false, fmt.Errorf("vote from %s: not a staked validator", v.Voter)
	}
	pub, ok := c.validatorPubs[v.Voter]
	if !ok || !pub.Equal(v.VoterPub) {
		return false, fmt.Errorf("vote from %s: public key does not match known validator key", v.Voter)
	}
	if v.Height <= c.finalizedHeight {
		return false, nil // already final (or genesis); nothing to do, not an error
	}
	if v.Height >= uint64(len(c.blocks)) {
		c.bufferVoteLocked(v)
		return false, nil
	}
	if c.blocks[v.Height].Hash != v.BlockHash {
		return false, fmt.Errorf("vote from %s: block hash does not match chain at height %d", v.Voter, v.Height)
	}

	byVoter := c.votesByHeight[v.Height]
	if byVoter == nil {
		byVoter = make(map[string]types.Vote)
		c.votesByHeight[v.Height] = byVoter
	}
	if existing, ok := byVoter[v.Voter]; ok {
		if existing.BlockHash != v.BlockHash {
			// Equivocation: this validator already voted for a different
			// block at this height. We don't implement slashing, but we
			// never let a later conflicting vote overwrite the first -
			// otherwise an equivocating validator could retroactively pick
			// which fork gets credit for its stake.
			return false, fmt.Errorf("vote from %s: conflicting vote for height %d (equivocation, ignored)", v.Voter, v.Height)
		}
		return false, nil // duplicate of a vote we already have
	}
	byVoter[v.Voter] = v

	var votedStake uint64
	for voter := range byVoter {
		s, overflow := types.AddUint64(votedStake, c.stakes[voter])
		if overflow {
			// Unreachable in practice: votedStake is a subset-sum of
			// totalStake, which genesis already validated doesn't
			// overflow. Fail closed rather than finalize on a corrupt sum.
			return false, fmt.Errorf("internal error: voted-stake overflow at height %d", v.Height)
		}
		votedStake = s
	}

	if votedStakeExceedsTwoThirds(votedStake, c.totalStake) {
		c.finalizedHeight = v.Height
		c.finalizedHash = v.BlockHash
		c.gcFinalizedLocked()
		return true, nil
	}
	return false, nil
}

// votedStakeExceedsTwoThirds reports whether voted*3 > total*2, computed
// with arbitrary-precision integers so it stays exact regardless of how
// close voted/total sit to the uint64 range (a plain voted*3 could
// overflow uint64 well before total does).
func votedStakeExceedsTwoThirds(voted, total uint64) bool {
	lhs := new(big.Int).Mul(new(big.Int).SetUint64(voted), big.NewInt(3))
	rhs := new(big.Int).Mul(new(big.Int).SetUint64(total), big.NewInt(2))
	return lhs.Cmp(rhs) > 0
}

// bufferVoteLocked stashes a vote for a height we haven't reached yet, so
// it can be replayed once that block arrives (see replayPendingVotesLocked).
// Caller must hold c.mu.
func (c *Chain) bufferVoteLocked(v types.Vote) {
	total := 0
	for _, vs := range c.pendingVotes {
		total += len(vs)
	}
	if total >= maxPendingVotes {
		return // bounded buffer; the voter will typically re-gossip anyway
	}
	c.pendingVotes[v.Height] = append(c.pendingVotes[v.Height], v)
}

// replayPendingVotesLocked re-attempts any votes buffered for height now
// that the corresponding block has just been added, and reports whether
// any of them newly finalized a block. Caller must hold c.mu.
func (c *Chain) replayPendingVotesLocked(height uint64) bool {
	pending := c.pendingVotes[height]
	if len(pending) == 0 {
		return false
	}
	delete(c.pendingVotes, height)
	finalized := false
	for _, v := range pending {
		ok, _ := c.addVoteLocked(v) // errors ignored: best-effort replay
		if ok {
			finalized = true
		}
	}
	return finalized
}

// gcFinalizedLocked drops vote/pending-vote bookkeeping for heights that
// are now finalized (or older), since a finalized height can never be
// un-finalized and its votes will never be consulted again. Caller must
// hold c.mu.
func (c *Chain) gcFinalizedLocked() {
	for h := range c.votesByHeight {
		if h <= c.finalizedHeight {
			delete(c.votesByHeight, h)
		}
	}
	for h := range c.pendingVotes {
		if h <= c.finalizedHeight {
			delete(c.pendingVotes, h)
		}
	}
}
