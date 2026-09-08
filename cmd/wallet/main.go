// Command wallet generates and inspects ed25519 account keypairs used by
// the node and tx tools.
package main

import (
	"flag"
	"fmt"
	"os"

	"claude-blockchain/internal/wallet"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "new":
		fs := flag.NewFlagSet("new", flag.ExitOnError)
		out := fs.String("out", "wallet.json", "output wallet file")
		fs.Parse(os.Args[2:])

		if _, err := os.Stat(*out); err == nil {
			fmt.Fprintf(os.Stderr, "refusing to overwrite existing file %s\n", *out)
			os.Exit(1)
		}
		w, err := wallet.New()
		if err != nil {
			fatal(err)
		}
		if err := w.Save(*out); err != nil {
			fatal(err)
		}
		fmt.Printf("wrote %s\naddress: %s\n", *out, w.Address)

	case "address":
		fs := flag.NewFlagSet("address", flag.ExitOnError)
		in := fs.String("wallet", "wallet.json", "wallet file")
		fs.Parse(os.Args[2:])

		w, err := wallet.Load(*in)
		if err != nil {
			fatal(err)
		}
		fmt.Println(w.Address)

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  wallet new -out <file>         generate a new keypair and save it
  wallet address -wallet <file>  print the address for an existing wallet`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
