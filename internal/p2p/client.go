package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"

	"claude-blockchain/internal/types"
)

// dialEphemeral connects to nodeAddr as a one-shot, non-peer client (used
// by the `tx` CLI) over TLS, confirms the node reports the expected chain,
// and returns the open connection for the caller to send one request on.
//
// This gets the same transport encryption a peer connection gets, using a
// throwaway Ed25519 identity generated for this process only. Unlike a
// long-lived node, a one-shot CLI invocation has no persistent state to
// pin the server's key against across calls, so - unlike Node's
// TOFU-pinned peer connections - this does not protect against a
// network-level attacker substituting a different node at the same
// address. What it still gets you: passive eavesdroppers can't read the
// transaction on the wire, and every transaction/block is separately
// signed end-to-end regardless of transport, so a substituted node cannot
// forge transactions from your key - it can at most refuse to relay them
// or lie about chain state, both of which are detectable by cross-checking
// against another node.
func dialEphemeral(nodeAddr, chainID string) (*Peer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client identity: %w", err)
	}
	cert, err := selfSignedCert(priv)
	if err != nil {
		return nil, err
	}

	rawConn, err := net.DialTimeout("tcp", nodeAddr, ioTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", nodeAddr, err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // see doc comment: no persistent pin store for a one-shot client
	})
	if err := handshakeWithDeadline(tlsConn); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", nodeAddr, err)
	}

	peer := newPeer(tlsConn)

	// ListenAddr "" marks this as an ephemeral client: the node will
	// process our message but won't register us as a routable peer.
	hello, err := newEnvelope(msgHello, helloMsg{ChainID: chainID, ListenAddr: ""})
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	if err := peer.send(hello); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if env, err := peer.recv(); err == nil && env.Type == msgHello {
		var h helloMsg
		if json.Unmarshal(env.Data, &h) == nil && h.ChainID != "" && h.ChainID != chainID {
			tlsConn.Close()
			return nil, fmt.Errorf("node %s is on chain %q, expected %q", nodeAddr, h.ChainID, chainID)
		}
	}
	return peer, nil
}

// SendTransaction dials nodeAddr and submits tx, waiting for the node's
// accept/reject response so a submission failure (bad nonce, insufficient
// balance, fee too low, wrong chain) is reported back to the caller
// instead of silently vanishing.
func SendTransaction(nodeAddr, chainID string, tx types.Transaction) error {
	peer, err := dialEphemeral(nodeAddr, chainID)
	if err != nil {
		return err
	}
	defer peer.close()

	txEnv, err := newEnvelope(msgTx, tx)
	if err != nil {
		return err
	}
	if err := peer.send(txEnv); err != nil {
		return fmt.Errorf("send tx: %w", err)
	}

	for {
		env, err := peer.recv()
		if err != nil {
			return fmt.Errorf("read response: %w", err)
		}
		if env.Type != msgTxResult {
			continue
		}
		var result txResultMsg
		if err := json.Unmarshal(env.Data, &result); err != nil {
			return err
		}
		if !result.Accepted {
			return fmt.Errorf("node rejected transaction: %s", result.Reason)
		}
		return nil
	}
}

// QueryAccount dials nodeAddr as an ephemeral client and fetches the
// current balance/nonce/stake for address.
func QueryAccount(nodeAddr, chainID, address string) (AccountInfo, error) {
	peer, err := dialEphemeral(nodeAddr, chainID)
	if err != nil {
		return AccountInfo{}, err
	}
	defer peer.close()

	req, err := newEnvelope(msgGetAccount, getAccountMsg{Address: address})
	if err != nil {
		return AccountInfo{}, err
	}
	if err := peer.send(req); err != nil {
		return AccountInfo{}, fmt.Errorf("send query: %w", err)
	}

	for {
		env, err := peer.recv()
		if err != nil {
			return AccountInfo{}, fmt.Errorf("read response: %w", err)
		}
		if env.Type != msgAccount {
			continue
		}
		var info AccountInfo
		if err := json.Unmarshal(env.Data, &info); err != nil {
			return AccountInfo{}, err
		}
		return info, nil
	}
}

// QueryParams dials nodeAddr as an ephemeral client and fetches the
// network's current consensus/economic parameters (minimum fee, block
// limits, finality depth), so callers like the `tx` CLI don't have to
// hardcode or guess them.
func QueryParams(nodeAddr, chainID string) (NetworkParams, error) {
	peer, err := dialEphemeral(nodeAddr, chainID)
	if err != nil {
		return NetworkParams{}, err
	}
	defer peer.close()

	req, err := newEnvelope(msgGetParams, nil)
	if err != nil {
		return NetworkParams{}, err
	}
	if err := peer.send(req); err != nil {
		return NetworkParams{}, fmt.Errorf("send query: %w", err)
	}

	for {
		env, err := peer.recv()
		if err != nil {
			return NetworkParams{}, fmt.Errorf("read response: %w", err)
		}
		if env.Type != msgParams {
			continue
		}
		var params NetworkParams
		if err := json.Unmarshal(env.Data, &params); err != nil {
			return NetworkParams{}, err
		}
		return params, nil
	}
}
