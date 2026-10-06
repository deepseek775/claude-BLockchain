// Command node runs a single blockchain P2P node: it maintains the chain,
// gossips transactions and blocks with peers, and - if given a wallet whose
// address holds stake in genesis - participates in proof-of-stake block
// proposal.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"claude-blockchain/internal/chain"
	"claude-blockchain/internal/genesis"
	"claude-blockchain/internal/mempool"
	"claude-blockchain/internal/p2p"
	"claude-blockchain/internal/wallet"
)

func main() {
	genesisPath := flag.String("genesis", "genesis.json", "path to genesis configuration")
	walletPath := flag.String("wallet", "", "path to this node's wallet file (omit to run as a non-validating full node)")
	listenAddr := flag.String("listen", ":26656", "address to listen for peers on")
	advertiseAddr := flag.String("advertise", "", "address other nodes should dial to reach us (default: same as -listen)")
	peers := flag.String("peers", "", "comma-separated list of bootstrap peer addresses")
	dataDir := flag.String("datadir", "", "directory to persist the block log in (omit to run in-memory only)")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	g, err := genesis.Load(*genesisPath)
	if err != nil {
		logger.Fatalf("load genesis: %v", err)
	}

	var logPath string
	if *dataDir != "" {
		if err := os.MkdirAll(*dataDir, 0o755); err != nil {
			logger.Fatalf("create datadir: %v", err)
		}
		logPath = filepath.Join(*dataDir, "blocks.log")
	}

	c, err := chain.New(g, logPath)
	if err != nil {
		logger.Fatalf("init chain: %v", err)
	}
	defer c.Close()
	logger.Printf("chain %q loaded at height %d", g.ChainID, c.Height())

	var w *wallet.Wallet
	if *walletPath != "" {
		passphrase, err := wallet.ResolvePassphrase(*walletPath, "WALLET_PASSPHRASE")
		if err != nil {
			logger.Fatalf("resolve wallet passphrase: %v", err)
		}
		w, err = wallet.Load(*walletPath, passphrase)
		if err != nil {
			logger.Fatalf("load wallet: %v", err)
		}
		stake := c.GetStake(w.Address)
		if stake == 0 {
			logger.Printf("warning: wallet %s has zero stake in genesis; it will never be selected to propose blocks", w.Address)
		} else {
			logger.Printf("running as validator %s (stake %d)", w.Address, stake)
		}
	} else {
		logger.Printf("running as a non-validating full node (no -wallet given)")
	}

	advertise := *advertiseAddr
	if advertise == "" {
		advertise = *listenAddr
	}

	var bootstrap []string
	if *peers != "" {
		for _, p := range strings.Split(*peers, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				bootstrap = append(bootstrap, p)
			}
		}
	}

	node, err := p2p.New(p2p.Config{
		ListenAddr:     *listenAddr,
		AdvertiseAddr:  advertise,
		BootstrapPeers: bootstrap,
		Chain:          c,
		Mempool:        mempool.New(),
		Wallet:         w,
		Logger:         logger,
	})
	if err != nil {
		logger.Fatalf("init p2p node: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("shutting down...")
		cancel()
	}()

	if err := node.Run(ctx); err != nil {
		logger.Fatal(err)
	}
	fmt.Println("node stopped")
}
