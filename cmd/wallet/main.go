// Command wallet generates and inspects ed25519 account keypairs used by
// the node and tx tools. Wallets are encrypted at rest by default: a
// plaintext private key on disk is a bearer instrument for whatever it
// holds, and encrypting it is the single highest-value protection this
// tool can give an account meant to hold real value.
package main

import (
	"flag"
	"fmt"
	"os"

	"claude-blockchain/internal/wallet"
)

const passphraseEnvVar = "WALLET_PASSPHRASE"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "new":
		cmdNew(os.Args[2:])
	case "address":
		cmdAddress(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func cmdNew(args []string) {
	fs := flag.NewFlagSet("new", flag.ExitOnError)
	out := fs.String("out", "wallet.json", "output wallet file")
	insecurePlaintext := fs.Bool("insecure-plaintext", false, "write an UNENCRYPTED wallet (only ever appropriate for disposable test wallets)")
	fs.Parse(args)

	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "refusing to overwrite existing file %s\n", *out)
		os.Exit(1)
	}
	w, err := wallet.New()
	if err != nil {
		fatal(err)
	}

	if *insecurePlaintext {
		if err := w.SaveInsecurePlaintext(*out); err != nil {
			fatal(err)
		}
		fmt.Fprintln(os.Stderr, "WARNING: wrote an unencrypted private key to disk. Do not use this wallet for anything of value.")
	} else {
		passphrase, err := resolveNewPassphrase()
		if err != nil {
			fatal(err)
		}
		if err := w.Save(*out, passphrase); err != nil {
			fatal(err)
		}
	}
	fmt.Printf("wrote %s\naddress: %s\n", *out, w.Address)
}

func cmdAddress(args []string) {
	fs := flag.NewFlagSet("address", flag.ExitOnError)
	in := fs.String("wallet", "wallet.json", "wallet file")
	fs.Parse(args)

	passphrase, err := wallet.ResolvePassphrase(*in, passphraseEnvVar)
	if err != nil {
		fatal(err)
	}
	w, err := wallet.Load(*in, passphrase)
	if err != nil {
		fatal(err)
	}
	fmt.Println(w.Address)
}

// resolveNewPassphrase prefers WALLET_PASSPHRASE (for scripted/CI wallet
// creation) and otherwise prompts interactively with confirmation.
func resolveNewPassphrase() (string, error) {
	if v, ok := os.LookupEnv(passphraseEnvVar); ok {
		if v == "" {
			return "", fmt.Errorf("%s is set but empty", passphraseEnvVar)
		}
		return v, nil
	}
	return wallet.PromptNewPassphrase()
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  wallet new -out <file> [-insecure-plaintext]   generate a new keypair and save it
  wallet address -wallet <file>                  print the address for an existing wallet

Passphrase resolution: set %s to avoid an interactive prompt
(useful in scripts/CI); otherwise you'll be prompted on the terminal.
`, passphraseEnvVar)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
