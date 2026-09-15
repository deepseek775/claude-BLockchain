package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// Every P2P connection is wrapped in mutually authenticated TLS 1.3. There
// is no public CA for a permissionless P2P network, so both sides present
// a self-signed certificate built from their own Ed25519 identity key
// (the node's wallet key if it has one, otherwise an ephemeral key
// generated at startup) and verification is done at the application layer
// instead of via a certificate chain:
//
//   - Outbound (dial): we already know which address we're calling, so we
//     verify the presented certificate's public key against a pinned value
//     for that address (trust-on-first-use, the same model SSH uses) via
//     VerifyPeerCertificate, which runs as part of the TLS handshake -
//     a mismatch aborts the connection before any application data is
//     exchanged.
//   - Inbound (accept): we don't know who's calling until their `hello`
//     arrives at the application layer, so pinning happens just after
//     that (see Node.verifyInboundIdentity in handlers.go).
//
// This protects gossip traffic against passive eavesdropping and
// network-level tampering/injection; it does not by itself replace the
// per-message Ed25519 signatures on transactions and blocks, which remain
// the source of truth for whether a transaction or block is authentic.

func selfSignedCert(key ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "claude-blockchain-node"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// peerCertKey extracts the Ed25519 public key from the first certificate a
// TLS peer presented.
func peerCertKey(cs tls.ConnectionState) (ed25519.PublicKey, error) {
	if len(cs.PeerCertificates) == 0 {
		return nil, fmt.Errorf("peer presented no certificate")
	}
	pub, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer certificate uses an unsupported key type")
	}
	return pub, nil
}

// serverTLSConfig requires (but, at the TLS layer, does not verify) a
// client certificate; identity verification for inbound connections
// happens post-handshake once we know who's claiming to connect (see
// verifyInboundIdentity).
func (n *Node) serverTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{n.tlsCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}
}

// clientTLSConfig pins the certificate presented by whoever answers at
// expectedAddr against any previously-seen key for that address.
func (n *Node) clientTLSConfig(expectedAddr string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{n.tlsCert},
		// No public CA exists for these self-signed identities, so the
		// default chain verification is meaningless here; VerifyPeerCertificate
		// below does the verification that matters (TOFU pinning).
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("server certificate uses an unsupported key type")
			}
			return n.checkOrPin(expectedAddr, pub)
		},
	}
}

// checkOrPin enforces trust-on-first-use: the first key seen for addr is
// remembered; any later connection presenting a different key for the same
// addr is rejected as a likely impersonation/MITM attempt (or, more
// mundanely, a validator that rotated its identity key without operator
// coordination - either way, a human should look at it before we proceed).
func (n *Node) checkOrPin(addr string, key ed25519.PublicKey) error {
	n.pinsMu.Lock()
	defer n.pinsMu.Unlock()
	if existing, ok := n.pins[addr]; ok {
		if !existing.Equal(key) {
			return fmt.Errorf("certificate for %s does not match previously pinned key (possible impersonation)", addr)
		}
		return nil
	}
	n.pins[addr] = key
	return nil
}
