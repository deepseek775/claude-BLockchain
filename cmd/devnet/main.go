// Command devnet generates a throwaway local N-validator network (wallets
// + a matching genesis.json) for `docker compose up` or manual testing.
//
// Nothing it writes is meant to be committed to version control or reused
// for a network that will hold real value: it exists so this repository
// doesn't need to ship demo private keys, while still giving you a
// one-command path to a running local network. A real network's genesis
// and validator keys must be generated and distributed out-of-band by
// each validator operator instead.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"claude-blockchain/internal/genesis"
	"claude-blockchain/internal/wallet"
)

func main() {
	out := flag.String("out", "deploy", "output directory")
	n := flag.Int("n", 3, "number of validator nodes to generate")
	chainID := flag.String("chain-id", "local-devnet", "chain id for the generated genesis")
	stakesFlag := flag.String("stakes", "", "comma-separated per-node stake (default: a descending sequence)")
	balance := flag.Uint64("balance", 1_000_000, "starting balance for every generated account")
	minFee := flag.Uint64("min-fee", 1, "minimum transaction fee")
	minValidatorStake := flag.Uint64("min-validator-stake", 100, "minimum stake to be eligible as a validator")
	finalityDepth := flag.Uint64("finality-depth", 100, "blocks before a block is treated as irreversible")
	blockSeconds := flag.Int("block-seconds", 5, "target seconds between blocks")
	maxTxPerBlock := flag.Int("max-tx-per-block", 500, "maximum transactions per block")
	maxBlockBytes := flag.Int("max-block-bytes", 2*1024*1024, "maximum serialized block size in bytes")
	force := flag.Bool("force", false, "overwrite an existing output directory")
	flag.Parse()

	if *n < 1 {
		fatal(fmt.Errorf("-n must be at least 1"))
	}

	if _, err := os.Stat(*out); err == nil {
		if !*force {
			fatal(fmt.Errorf("%s already exists (pass -force to overwrite - this deletes it first)", *out))
		}
		if err := os.RemoveAll(*out); err != nil {
			fatal(err)
		}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}

	stakes := parseStakes(*stakesFlag, *n)

	g := genesis.Genesis{
		ProtocolVersion:   genesis.ProtocolVersion,
		ChainID:           *chainID,
		Timestamp:         time.Now().Unix(),
		BlockTimeSeconds:  *blockSeconds,
		MaxTxPerBlock:     *maxTxPerBlock,
		MaxBlockBytes:     *maxBlockBytes,
		MinFee:            *minFee,
		MinValidatorStake: *minValidatorStake,
		FinalityDepth:     *finalityDepth,
	}

	envLines := make([]string, 0, *n)
	for i := 1; i <= *n; i++ {
		nodeDir := filepath.Join(*out, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(nodeDir, 0o755); err != nil {
			fatal(err)
		}

		w, err := wallet.New()
		if err != nil {
			fatal(err)
		}
		passphrase, err := randomPassphrase()
		if err != nil {
			fatal(err)
		}
		walletPath := filepath.Join(nodeDir, "wallet.json")
		if err := w.Save(walletPath, passphrase); err != nil {
			fatal(err)
		}

		envLines = append(envLines, fmt.Sprintf("NODE%d_PASSPHRASE=%s", i, passphrase))
		g.Accounts = append(g.Accounts, genesis.Account{
			Address:   w.Address,
			PublicKey: hex.EncodeToString(w.PublicKey),
			Balance:   *balance,
			Stake:     stakes[i-1],
		})
		fmt.Printf("node%d: %s (stake %d)\n", i, w.Address, stakes[i-1])
	}

	genesisPath := filepath.Join(*out, "genesis.json")
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(genesisPath, data, 0o644); err != nil {
		fatal(err)
	}

	envPath := filepath.Join(*out, ".env")
	if err := os.WriteFile(envPath, []byte(strings.Join(envLines, "\n")+"\n"), 0o600); err != nil {
		fatal(err)
	}

	fmt.Printf(`
Generated a local devnet under %s (do not commit this directory):
  - %s
  - %s/node{1..%d}/wallet.json (encrypted; passphrases in %s)
  - %s (per-node wallet passphrases, for the --env-file flag below)

Start it with (--env-file is required since docker compose only
auto-loads .env from the project root, not from %s):
  docker compose --env-file %s up --build

These keys are for local testing only. Never reuse a devnet wallet or
genesis file for a network that will hold real value.
`, *out, genesisPath, *out, *n, envPath, envPath, *out, envPath)
}

// parseStakes returns n stake values, either from a user-supplied
// comma-separated list or a sensible descending default.
func parseStakes(flagVal string, n int) []uint64 {
	if flagVal != "" {
		parts := strings.Split(flagVal, ",")
		if len(parts) != n {
			fatal(fmt.Errorf("-stakes has %d values but -n is %d", len(parts), n))
		}
		out := make([]uint64, n)
		for i, p := range parts {
			v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64)
			if err != nil {
				fatal(fmt.Errorf("-stakes: invalid value %q: %w", p, err))
			}
			out[i] = v
		}
		return out
	}
	out := make([]uint64, n)
	base := uint64(100 * (n + 2))
	for i := range out {
		out[i] = base - uint64(i)*100
	}
	return out
}

func randomPassphrase() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate passphrase: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
