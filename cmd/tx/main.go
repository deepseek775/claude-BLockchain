// Command tx is a thin client for submitting transactions to a running
// node and querying account/network state, without the node needing to
// expose any RPC surface beyond its normal (TLS-protected) P2P port.
package main

import (
	"flag"
	"fmt"
	"os"

	"claude-blockchain/internal/p2p"
	"claude-blockchain/internal/types"
	"claude-blockchain/internal/wallet"
)

const passphraseEnvVar = "WALLET_PASSPHRASE"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "send":
		cmdSend(os.Args[2:])
	case "balance":
		cmdBalance(os.Args[2:])
	case "params":
		cmdParams(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func cmdSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	node := fs.String("node", "127.0.0.1:26656", "node address to submit through")
	chainID := fs.String("chain-id", "", "expected chain id (required)")
	walletPath := fs.String("wallet", "wallet.json", "sender wallet file")
	to := fs.String("to", "", "recipient address (required)")
	amount := fs.Uint64("amount", 0, "amount to send (required, > 0)")
	fee := fs.Int64("fee", -1, "fee to pay the block proposer (default: auto-fetch the network minimum)")
	nonce := fs.Int64("nonce", -1, "override account nonce (default: auto-fetch)")
	fs.Parse(args)

	if *chainID == "" || *to == "" || *amount == 0 {
		fmt.Fprintln(os.Stderr, "send: -chain-id, -to, and -amount are required")
		os.Exit(2)
	}

	passphrase, err := wallet.ResolvePassphrase(*walletPath, passphraseEnvVar)
	if err != nil {
		fatal(err)
	}
	w, err := wallet.Load(*walletPath, passphrase)
	if err != nil {
		fatal(err)
	}

	n := uint64(*nonce)
	if *nonce < 0 {
		info, err := p2p.QueryAccount(*node, *chainID, w.Address)
		if err != nil {
			fatal(fmt.Errorf("fetch nonce: %w", err))
		}
		n = info.Nonce
	}

	f := uint64(*fee)
	if *fee < 0 {
		params, err := p2p.QueryParams(*node, *chainID)
		if err != nil {
			fatal(fmt.Errorf("fetch minimum fee: %w", err))
		}
		f = params.MinFee
	}

	txn := types.Transaction{
		ChainID: *chainID,
		From:    w.Address,
		To:      *to,
		Amount:  *amount,
		Fee:     f,
		Nonce:   n,
	}
	txn.Sign(w.PrivateKey)

	if err := p2p.SendTransaction(*node, *chainID, txn); err != nil {
		fatal(err)
	}
	fmt.Printf("accepted: %s -> %s amount=%d fee=%d nonce=%d\n", w.Address, *to, *amount, f, n)
}

func cmdBalance(args []string) {
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	node := fs.String("node", "127.0.0.1:26656", "node address to query")
	chainID := fs.String("chain-id", "", "expected chain id (required)")
	address := fs.String("address", "", "address to query (required)")
	fs.Parse(args)

	if *chainID == "" || *address == "" {
		fmt.Fprintln(os.Stderr, "balance: -chain-id and -address are required")
		os.Exit(2)
	}

	info, err := p2p.QueryAccount(*node, *chainID, *address)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("address: %s\nbalance: %d\nnonce:   %d\nstake:   %d\n", info.Address, info.Balance, info.Nonce, info.Stake)
}

func cmdParams(args []string) {
	fs := flag.NewFlagSet("params", flag.ExitOnError)
	node := fs.String("node", "127.0.0.1:26656", "node address to query")
	chainID := fs.String("chain-id", "", "expected chain id (required)")
	fs.Parse(args)

	if *chainID == "" {
		fmt.Fprintln(os.Stderr, "params: -chain-id is required")
		os.Exit(2)
	}

	p, err := p2p.QueryParams(*node, *chainID)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("chain_id:        %s\nmin_fee:         %d\nmax_tx_per_block: %d\nmax_block_bytes: %d\nfinality_depth:  %d\nblock_seconds:   %d\n",
		p.ChainID, p.MinFee, p.MaxTxPerBlock, p.MaxBlockBytes, p.FinalityDepth, p.BlockSeconds)
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  tx send -node <addr> -chain-id <id> -wallet <file> -to <addr> -amount <n> [-fee <n>] [-nonce <n>]
  tx balance -node <addr> -chain-id <id> -address <addr>
  tx params  -node <addr> -chain-id <id>

Passphrase resolution for encrypted wallets: set %s to avoid an
interactive prompt (useful in scripts/CI); otherwise you'll be prompted on
the terminal.
`, passphraseEnvVar)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
