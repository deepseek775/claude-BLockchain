// Command tx is a thin client for submitting transactions to a running
// node and querying account state, without the node needing to expose any
// RPC surface beyond its normal P2P port.
package main

import (
	"flag"
	"fmt"
	"os"

	"claude-blockchain/internal/p2p"
	"claude-blockchain/internal/types"
	"claude-blockchain/internal/wallet"
)

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
	nonce := fs.Int64("nonce", -1, "override account nonce (default: auto-fetch)")
	fs.Parse(args)

	if *chainID == "" || *to == "" || *amount == 0 {
		fmt.Fprintln(os.Stderr, "send: -chain-id, -to, and -amount are required")
		os.Exit(2)
	}

	w, err := wallet.Load(*walletPath)
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

	txn := types.Transaction{
		From:   w.Address,
		To:     *to,
		Amount: *amount,
		Nonce:  n,
	}
	txn.Sign(w.PrivateKey)

	if err := p2p.SendTransaction(*node, *chainID, txn); err != nil {
		fatal(err)
	}
	fmt.Printf("submitted: %s -> %s amount=%d nonce=%d\n", w.Address, *to, *amount, n)
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

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  tx send -node <addr> -chain-id <id> -wallet <file> -to <addr> -amount <n> [-nonce <n>]
  tx balance -node <addr> -chain-id <id> -address <addr>`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
