# claude-blockchain

A proof-of-stake blockchain in Go: Ed25519-signed and fee-priced
transactions, deterministic stake-weighted validator selection, mutually
authenticated TLS gossip networking with peer discovery and chain sync,
BFT-style instant finality (backed by depth-based reorg protection as a
fallback), passphrase-encrypted wallets, and crash-recoverable block-log
persistence. No demo keys are checked in -
`cmd/devnet` generates a throwaway local network on demand. Standard
library only, plus `golang.org/x/crypto` and `golang.org/x/term` for
wallet encryption (official Go team packages - no hand-rolled crypto).

**Read [Production readiness](#production-readiness) before you consider
using this for anything that touches real money.** Code-level hardening
(this document) is necessary but not sufficient for that.

## How it works

- **Accounts**: an Ed25519 keypair. The address is `0x` + the first 20
  bytes of `sha256(public key)`.
- **Transactions**: `chain_id`, `from`, `to`, `amount`, `fee`, `nonce`,
  signed with Ed25519. `chain_id` binds a transaction to one network
  (EIP-155-style), so a transaction valid on a testnet can't be replayed
  on a mainnet sharing the same address space. `fee` is paid to whichever
  validator proposes the including block - it deters mempool-flooding
  spam and is the validator's actual incentive to participate; the
  mempool serves pending transactions to a block proposer highest-fee
  first.
- **Blocks**: a batch of transactions plus the proposer's address, public
  key, signature, and `reward` (the summed fees, cross-checked against
  the transaction list). Chained by `prev_hash`; also chain-ID-bound.
- **Consensus (proof of stake)**: each genesis account is assigned a
  stake. For every block height, every node independently computes the
  same proposer via a stake-weighted lottery seeded by the previous
  block's hash (`internal/pos`). Whoever that is signs and broadcasts the
  next block; all other nodes verify the signature, the proposer's
  eligibility, every transaction, and the fee/reward accounting before
  accepting it.
- **BFT-style instant finality**: after accepting a block, every validator
  signs and gossips a commit `Vote` for it (`internal/types/vote.go`).
  Once votes from validators together holding more than 2/3 of total stake
  are collected for a block, it is finalized - and a finalized block can
  never be reorged, no matter how long a competing chain is
  (`internal/chain/finality.go`, enforced in `ReplaceChain`,
  `internal/chain/sync.go`). In a healthy network with most validators
  online, this typically finalizes a block within the same block period it
  was proposed in - not "probably safe after N confirmations," but a
  concrete, checkable cryptoeconomic guarantee. This is a simplified,
  single-round attestation scheme, not full Tendermint: no separate
  prevote/precommit phases, no view-change/timeout handling for a stalled
  round, and no slashing for equivocation (a validator signing conflicting
  votes at the same height has its second vote rejected, but isn't
  penalized). See the Production Readiness section for the full list of
  what this does and doesn't guarantee.
- **Finality depth (fallback)**: before a block collects enough votes to
  finalize - e.g. while validators are still catching up, or some are
  offline - a competing chain is still rejected if it would rewrite a
  block more than `finality_depth` blocks behind the current head, even if
  longer and otherwise valid. Proof-of-stake chains can't rely on "longest
  chain wins" alone the way proof-of-work can - producing an alternative
  history costs no real-world resource once a private key is known (a
  "long-range attack") - so this depth limit gives the chain a practical
  fallback notion of settlement finality for the window before BFT voting
  catches up. See `internal/chain/sync.go`.
- **Networking**: every connection is mutually authenticated TLS 1.3
  (`internal/p2p/tls.go`), framed as length-prefixed JSON on top. Nodes
  present self-signed certificates built from their own Ed25519 identity
  key; outbound connections pin the peer's key on first use (TOFU, the
  same trust model SSH uses) so a later MITM/impersonation attempt is
  rejected instead of silently accepted. Nodes gossip transactions,
  blocks, and finality votes, exchange peer lists, and can sync a full
  chain from a peer. Connections are capped per-IP and per-node to bound
  resource use under a connection flood.
- **Persistence**: each node optionally appends committed blocks to a
  local log file and replays it (revalidating every block) on restart.
- **Wallets**: private keys are encrypted at rest by default -
  scrypt (N=2^15, r=8, p=1) key derivation + AES-256-GCM, passphrase
  resolved from an environment variable or an interactive no-echo prompt.
  Plaintext wallets are only available via an explicit, loudly-labeled
  opt-out for disposable test wallets.

## Build & run locally

```sh
go build ./...
go test ./...

# generate a keypair (you'll be prompted for a passphrase)
go run ./cmd/wallet new -out wallet.json

# run a single node (needs a genesis.json - see "Local devnet" below to
# generate one, or write your own by hand per the field reference there)
go run ./cmd/node -genesis=genesis.json -wallet=wallet.json -listen=:26656

# send a transaction through any running node (fee defaults to the
# network minimum if -fee is omitted)
WALLET_PASSPHRASE=... go run ./cmd/tx send -node=127.0.0.1:26656 \
  -chain-id=<chain id from your genesis> -wallet=wallet.json \
  -to=0xRECIPIENT -amount=100

# check a balance, or the network's current parameters (including the
# latest BFT-finalized height)
go run ./cmd/tx balance -node=127.0.0.1:26656 -chain-id=<id> -address=0xADDR
go run ./cmd/tx params  -node=127.0.0.1:26656 -chain-id=<id>
```

`WALLET_PASSPHRASE` avoids an interactive prompt (useful in scripts/CI);
omit it and you'll be prompted on the terminal instead. `go test ./...`
covers transaction/block validation, fee accounting and overflow
rejection, chain-ID rejection, double-spend rejection, validator
eligibility, BFT vote finalization (supermajority threshold, equivocation
rejection, vote buffering), finality-depth reorg rejection, rejection of a
reorg past a finalized block, chain persistence/replay, wallet encryption
round-trips, and mempool fee-ordering/limits.

## Local devnet

```sh
go run ./cmd/devnet                          # 3 validators under ./deploy (gitignored)
docker compose --env-file deploy/.env up --build
```

`cmd/devnet` generates fresh, encrypted wallets and a matching
`genesis.json` under `./deploy` every time it runs - nothing it writes is
committed to this repository, and it isn't meant to be: private keys
belong in version control never, "for local testing" or otherwise. See
`go run ./cmd/devnet -h` for stake/balance/fee/finality flags.

Submit a transaction from the host once the network is up (addresses and
the chain ID are in `deploy/genesis.json`):

```sh
source deploy/.env
WALLET_PASSPHRASE=$NODE1_PASSPHRASE go run ./cmd/tx send \
  -node=127.0.0.1:26661 -chain-id=local-devnet \
  -wallet=deploy/node1/wallet.json -to=0x... -amount=1000
```

### Writing your own genesis.json

| field | meaning |
|---|---|
| `protocol_version` | must equal `genesis.ProtocolVersion` (currently `1`) for this build |
| `chain_id` | unique network identifier; every transaction/block is bound to it |
| `timestamp` | genesis block timestamp (unix seconds) |
| `block_time_seconds` | target seconds between blocks |
| `max_tx_per_block` / `max_block_bytes` | block size limits |
| `min_fee` | minimum transaction fee accepted |
| `min_validator_stake` | minimum stake for an account to be eligible as a validator |
| `finality_depth` | fallback: blocks before a block is treated as irreversible even without a 2/3-stake vote |
| `accounts` | `[{address, public_key (hex), balance, stake}]` - every node needs an identical copy |

## Project layout

```
cmd/node      node daemon: chain + P2P (TLS) + block proposal
cmd/tx        CLI to submit transactions / query balances & params via a node's P2P port
cmd/wallet    CLI to generate/inspect encrypted Ed25519 wallets
cmd/devnet    generates a throwaway local network (wallets + genesis.json)
internal/types      Transaction, Block and Vote: signing, verification, hashing, overflow-safe math
internal/pos        deterministic stake-weighted validator selection
internal/chain      validation, state, fee/reward accounting, persistence, BFT vote finality, finality-bounded sync
internal/mempool    pending-transaction pool: per-sender caps, fee-ordered selection
internal/genesis    genesis file loading/validation
internal/p2p        TLS-secured gossip networking, wire protocol, TOFU pinning
internal/wallet     encrypted keypair generation and on-disk storage
```

## Production readiness

This codebase implements real consensus/security mechanisms correctly to
the best of this review's ability - but **no amount of code review,
including this one, can certify software as safe to hold real value.**
That takes things no diff can provide:

- **An independent security audit** by a firm that specializes in
  consensus/cryptographic systems, ideally more than one. This code has
  not had one.
- **Legal and regulatory review.** Operating a payment network is
  regulated in most jurisdictions - money transmission licensing,
  AML/KYC obligations, sanctions screening, tax reporting. None of that
  is a code problem, and none of it is addressed here.
- **A testnet burn-in period** with real adversarial pressure (public
  bug bounty, third parties actually trying to break it) before any
  mainnet holds value.
- **Key custody infrastructure** beyond a passphrase-encrypted file on
  disk: HSMs or equivalent for validator keys, multi-sig or threshold
  signing for high-value accounts, documented incident response for a
  compromised key.
- **Operational monitoring and alerting**: chain-health metrics, alerting
  on missed blocks/forks/finality stalls, and a plan for what a validator
  operator does when one fires.

Known protocol-level limitations, so they're documented rather than
discovered the hard way:

- **No VRF.** The validator lottery's randomness comes from the previous
  block's hash, not a verifiable random function. Once a block is known,
  everyone can compute the next proposer - there's no unpredictability
  advantage attackers get over honest nodes, but it's not the
  cryptographic construction a production PoS chain would use.
- **Stake is fixed at genesis.** There are no bond/unbond transactions
  and no slashing for equivocation. A validator's stake, once set, never
  changes; a misbehaving validator can't be automatically penalized.
- **BFT finality is single-round, not full Tendermint.** There's one vote
  phase (a commit attestation), not Tendermint's separate prevote/precommit
  rounds with locking rules, so this doesn't carry the same formal
  Byzantine-safety proof under network partitions that full Tendermint
  does. There's also no view-change/timeout handling if a round stalls
  (e.g. the expected proposer is offline) - the chain just waits for the
  next height's proposer, falling back on `finality_depth` in the
  meantime - and no slashing for equivocation (a validator caught signing
  conflicting votes has the second one rejected, not penalized). The
  validator set is the same fixed, genesis-defined one the rest of this
  chain uses (see "stake is fixed at genesis" below); there's no dynamic
  quorum to reason about, which simplifies the threshold math but means
  finality strength is only as good as that fixed set's honesty.
- **BFT finality vote state isn't persisted across a restart.** The
  underlying blocks are (via the block log), so nothing is lost, but a
  restarted node's `finalized_height` resets to 0 until it collects fresh
  votes from the still-running network - which happens quickly in
  practice, but means a query hitting a node in the first moments after
  its own restart may under-report finality that the rest of the network
  already has.
- **A validator that fast-syncs past several blocks only votes for the new
  tip going forward**, not retroactively for every block it skipped. If
  enough other validators were online and voting in real time, those
  skipped blocks still reach finality without it; if not, they remain
  covered only by `finality_depth` until/unless later re-voted.
- **No transaction fee market beyond a fixed minimum and highest-fee-first
  selection** - no dynamic base fee, no fee estimation API.
- **TOFU pinning, not a PKI.** Outbound peer connections pin on first
  use; there's no certificate authority, so the very first connection to
  a given address is not itself protected against a MITM. This matches
  SSH's trust model, not TLS's usual one.
- **The `tx` CLI's connection to a node is not pinned** (a one-shot
  process has no persistent state to pin against). Transactions are still
  cryptographically safe to submit this way - they're signed end-to-end
  and a tampering node can't forge one - but a network-level attacker
  could substitute a different node at the same address and feed you
  false chain state. Cross-check balances against a second node for
  anything you care about.
