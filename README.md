# claude-blockchain

A small, from-scratch proof-of-stake blockchain in Go: P2P gossip networking,
Ed25519-signed transactions, deterministic stake-weighted validator
selection, and crash-recoverable persistence. No external dependencies —
standard library only.

This is an educational/demo chain, not a production network. See
[Security notes](#security-notes--known-limitations) for what that means in
practice.

## How it works

- **Accounts**: an Ed25519 keypair. The address is `0x` + the first 20 bytes
  of `sha256(public key)`.
- **Transactions**: `from`, `to`, `amount`, `nonce`, signed with Ed25519.
  Every field is covered by the signature.
- **Blocks**: a batch of transactions plus the proposer's address, public
  key, and signature. Chained by `prev_hash`.
- **Consensus (proof of stake)**: each genesis account is assigned a stake.
  For every block height, every node independently computes the same
  proposer via a stake-weighted lottery seeded by the previous block's hash
  (`internal/pos`). Whoever that is signs and broadcasts the next block; all
  other nodes verify the signature, the proposer's eligibility, and every
  transaction before accepting it.
- **Networking**: plain TCP with length-prefixed JSON messages
  (`internal/p2p`). Nodes gossip transactions and blocks, exchange peer
  lists, and can sync a full chain from a peer (used on startup and when a
  node falls behind).
- **Persistence**: each node optionally appends committed blocks to a local
  log file and replays it on restart, so a restart doesn't require a full
  re-sync.

## Build & run locally

```sh
go build ./...

# generate a keypair for a validator
go run ./cmd/wallet new -out wallet.json

# run a single node (see genesis.json for the demo validator set/stakes)
go run ./cmd/node -genesis=genesis.json -wallet=wallet.json -listen=:26656

# send a transaction through any running node
go run ./cmd/tx send -node=127.0.0.1:26656 -chain-id=claude-demo \
  -wallet=wallet.json -to=0xRECIPIENT -amount=100

# check a balance
go run ./cmd/tx balance -node=127.0.0.1:26656 -chain-id=claude-demo -address=0xADDR
```

Run `go test ./...` to run the unit tests (transaction/block validation,
double-spend rejection, validator eligibility, chain persistence and
replay, stake-weighted selection).

## Run a 3-node network with Docker

`genesis.json` and `examples/node{1,2,3}/wallet.json` are a ready-made demo
network: three validators with stakes 500/300/200. **These wallets are
public demo keys checked into this repo — never reuse them for anything of
value.**

```sh
docker compose up --build
```

This starts three nodes (`node1`, `node2`, `node3`) that discover each
other, elect proposers by stake, and produce a block roughly every 5
seconds. Ports 26661-26663 on the host map to each node's P2P port.

Submit a transaction from the host once the network is up:

```sh
go run ./cmd/tx send -node=127.0.0.1:26661 -chain-id=claude-demo \
  -wallet=examples/node1/wallet.json \
  -to=0x9a5646c8775b53cec4642a7c34c0ba8013ea012c -amount=1000
```

### Generating your own network

```sh
go run ./cmd/wallet new -out examples/nodeN/wallet.json
```

Then add an entry to `genesis.json`'s `accounts` array with that wallet's
`address`, `public_key`, an initial `balance`, and a `stake` (only accounts
with stake > 0 are ever selected to propose blocks).

## Project layout

```
cmd/node      node daemon: chain + P2P + block proposal
cmd/tx        CLI to submit transactions / query balances via a node's P2P port
cmd/wallet    CLI to generate/inspect Ed25519 wallets
internal/types      Transaction and Block: signing, verification, hashing
internal/pos        deterministic stake-weighted validator selection
internal/chain      block/transaction validation, state, persistence, sync
internal/mempool    pending-transaction pool
internal/genesis    genesis file loading/validation
internal/p2p        TCP gossip networking and wire protocol
internal/wallet     keypair generation and on-disk storage
```

## Security notes & known limitations

Deliberate trade-offs made to keep this small, documented rather than hidden:

- **No VRF.** The validator lottery's randomness comes from the previous
  block's hash, not a verifiable random function. Once a block is known,
  everyone can compute the next proposer - there's no unpredictability
  advantage attackers get over honest nodes, but it's not the
  cryptographic construction a production PoS chain would use.
- **Stake is fixed at genesis.** There are no stake/unstake transactions.
  A production chain would let validators bond/unbond stake, with slashing
  for equivocation.
- **No fork-choice beyond "longest valid chain."** `ReplaceChain` accepts a
  longer valid chain from any peer; there's no weighting by stake or
  finality gadget, so a well-resourced adversary controlling many peer
  connections could in principle feed a node a competing valid chain. Real
  PoS chains add explicit finality (e.g. a 2/3-stake voting round).
- **No transaction fees or block rewards.** Total supply is fixed at
  genesis.
- Every signature (transactions and blocks) is verified before being
  applied; balances/nonces are re-checked against a fresh state copy so a
  batch of transactions can't double-spend within one block.
- Wire messages are length-prefixed and capped at 8MB; connections use read
  and write deadlines. Both limit resource-exhaustion attacks from a
  malicious peer.
- Wallet files are written with `0600` permissions (owner read/write only).
- The node process runs as a non-root user in the Docker image.
