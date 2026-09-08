package p2p

import (
	"encoding/json"
	"fmt"
	"net"

	"claude-blockchain/internal/types"
)

// SendTransaction dials nodeAddr as a one-shot, non-peer client, confirms
// the node is on the expected chain, and submits tx for broadcast. It is
// used by the `tx` CLI tool so a user can send value without the node
// needing a separate RPC/HTTP surface (one less thing to secure).
func SendTransaction(nodeAddr, chainID string, tx types.Transaction) error {
	conn, err := net.DialTimeout("tcp", nodeAddr, ioTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", nodeAddr, err)
	}
	defer conn.Close()
	peer := newPeer(conn)

	// ListenAddr "" marks this as an ephemeral client: the node will
	// process our message but won't register us as a routable peer.
	hello, err := newEnvelope(msgHello, helloMsg{ChainID: chainID, ListenAddr: ""})
	if err != nil {
		return err
	}
	if err := peer.send(hello); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	if env, err := peer.recv(); err == nil && env.Type == msgHello {
		var h helloMsg
		if json.Unmarshal(env.Data, &h) == nil && h.ChainID != "" && h.ChainID != chainID {
			return fmt.Errorf("node %s is on chain %q, expected %q", nodeAddr, h.ChainID, chainID)
		}
	}

	txEnv, err := newEnvelope(msgTx, tx)
	if err != nil {
		return err
	}
	if err := peer.send(txEnv); err != nil {
		return fmt.Errorf("send tx: %w", err)
	}
	return nil
}

// QueryAccount dials nodeAddr as an ephemeral client and fetches the
// current balance/nonce/stake for address.
func QueryAccount(nodeAddr, chainID, address string) (AccountInfo, error) {
	conn, err := net.DialTimeout("tcp", nodeAddr, ioTimeout)
	if err != nil {
		return AccountInfo{}, fmt.Errorf("dial %s: %w", nodeAddr, err)
	}
	defer conn.Close()
	peer := newPeer(conn)

	hello, err := newEnvelope(msgHello, helloMsg{ChainID: chainID, ListenAddr: ""})
	if err != nil {
		return AccountInfo{}, err
	}
	if err := peer.send(hello); err != nil {
		return AccountInfo{}, fmt.Errorf("handshake: %w", err)
	}
	if env, err := peer.recv(); err == nil && env.Type == msgHello {
		var h helloMsg
		if json.Unmarshal(env.Data, &h) == nil && h.ChainID != "" && h.ChainID != chainID {
			return AccountInfo{}, fmt.Errorf("node %s is on chain %q, expected %q", nodeAddr, h.ChainID, chainID)
		}
	}

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
