package wallet

import (
	"path/filepath"
	"testing"
)

func TestEncryptedRoundTrip(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := w.Save(path, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	encrypted, err := IsEncrypted(path)
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Fatal("expected Save to write an encrypted wallet")
	}

	loaded, err := Load(path, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Address != w.Address {
		t.Fatalf("address mismatch: got %s, want %s", loaded.Address, w.Address)
	}
	if !loaded.PrivateKey.Equal(w.PrivateKey) {
		t.Fatal("private key did not round-trip correctly")
	}
}

func TestLoadRejectsWrongPassphrase(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := w.Save(path, "right passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "wrong passphrase"); err == nil {
		t.Fatal("expected Load with wrong passphrase to fail")
	}
}

func TestLoadRejectsEmptyPassphraseOnEncryptedWallet(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := w.Save(path, "a passphrase"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, ""); err == nil {
		t.Fatal("expected Load with empty passphrase to fail on an encrypted wallet")
	}
}

func TestSaveRejectsEmptyPassphrase(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := w.Save(path, ""); err == nil {
		t.Fatal("expected Save with empty passphrase to be refused")
	}
}

func TestInsecurePlaintextRoundTrip(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "wallet.json")
	if err := w.SaveInsecurePlaintext(path); err != nil {
		t.Fatal(err)
	}
	encrypted, err := IsEncrypted(path)
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		t.Fatal("expected SaveInsecurePlaintext to write an unencrypted wallet")
	}
	loaded, err := Load(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.PrivateKey.Equal(w.PrivateKey) {
		t.Fatal("private key did not round-trip correctly")
	}
}
