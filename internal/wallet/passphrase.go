package wallet

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/term"
)

// ResolvePassphrase determines the passphrase to use for a wallet at path.
// If the wallet isn't encrypted, it returns "" immediately without
// prompting. Otherwise it tries, in order: the named environment variable
// (for non-interactive contexts like a container with no TTY - documented
// as the weaker option since it can leak via process listings or a
// misconfigured log/crash dump), then an interactive no-echo terminal
// prompt. It fails rather than silently falling back to a lower-security
// option the caller didn't ask for.
func ResolvePassphrase(walletPath, envVar string) (string, error) {
	encrypted, err := IsEncrypted(walletPath)
	if err != nil {
		return "", err
	}
	if !encrypted {
		return "", nil
	}

	if envVar != "" {
		if v, ok := os.LookupEnv(envVar); ok {
			if v == "" {
				return "", fmt.Errorf("wallet: %s is set but empty", envVar)
			}
			return v, nil
		}
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("wallet: %s is encrypted, no %s set, and stdin is not a terminal to prompt on", walletPath, envVar)
	}
	return promptPassphrase(fmt.Sprintf("passphrase for %s: ", walletPath))
}

// PromptNewPassphrase interactively prompts for a new passphrase twice and
// confirms both entries match, for wallet creation.
func PromptNewPassphrase() (string, error) {
	p1, err := promptPassphrase("new wallet passphrase: ")
	if err != nil {
		return "", err
	}
	if p1 == "" {
		return "", fmt.Errorf("wallet: passphrase must not be empty")
	}
	p2, err := promptPassphrase("confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", fmt.Errorf("wallet: passphrases did not match")
	}
	return p1, nil
}

func promptPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		return string(b), nil
	}
	// Non-terminal stdin (e.g. piped input in a script/test): fall back to
	// a plain line read rather than failing outright.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line, nil
}
