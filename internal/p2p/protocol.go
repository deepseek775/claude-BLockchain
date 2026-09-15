// Package p2p implements a minimal gossip network: nodes exchange
// transactions, blocks, and peer addresses over plain TCP using
// length-prefixed JSON messages. There is no discovery service - networks
// are formed by giving each node a list of bootstrap peer addresses.
package p2p

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxFrameSize bounds a single message on the wire. Without a cap, a
// malicious or buggy peer could send an arbitrarily large length prefix and
// exhaust this node's memory before any validation happens.
const maxFrameSize = 8 * 1024 * 1024 // 8MB, generous for a full chain sync reply

type msgType string

const (
	msgHello      msgType = "hello"
	msgGetPeers   msgType = "get_peers"
	msgPeers      msgType = "peers"
	msgTx         msgType = "tx"
	msgBlock      msgType = "block"
	msgGetChain   msgType = "get_chain"
	msgChain      msgType = "chain"
	msgGetAccount msgType = "get_account"
	msgAccount    msgType = "account"
	msgTxResult   msgType = "tx_result"
	msgGetParams  msgType = "get_params"
	msgParams     msgType = "params"
)

// envelope is the wire format for every message: a type tag plus a
// type-specific JSON payload.
type envelope struct {
	Type msgType         `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

func newEnvelope(t msgType, payload any) (envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return envelope{}, err
	}
	return envelope{Type: t, Data: data}, nil
}

var errFrameTooLarge = errors.New("p2p: incoming frame exceeds maximum size")

// writeFrame writes env to w as a 4-byte big-endian length prefix followed
// by its JSON encoding.
func writeFrame(w io.Writer, env envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > maxFrameSize {
		return errFrameTooLarge
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// readFrame reads one length-prefixed message from r.
func readFrame(r io.Reader) (envelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return envelope{}, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxFrameSize {
		return envelope{}, errFrameTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return envelope{}, err
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return envelope{}, fmt.Errorf("p2p: malformed envelope: %w", err)
	}
	return env, nil
}

// helloMsg identifies the sender to a new peer: its chain (so incompatible
// networks refuse each other immediately) and the address other nodes
// should use to dial it back.
type helloMsg struct {
	ChainID    string `json:"chain_id"`
	ListenAddr string `json:"listen_addr"`
}

type peersMsg struct {
	Addrs []string `json:"addrs"`
}

type getAccountMsg struct {
	Address string `json:"address"`
}

// AccountInfo is the read-only account state returned in response to a
// get_account query.
type AccountInfo struct {
	Address string `json:"address"`
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
	Stake   uint64 `json:"stake"`
}

// txResultMsg tells an ephemeral client (see the `tx` CLI) whether the
// transaction it just submitted was accepted into the mempool, so
// submission failures (bad nonce, insufficient balance, fee too low,
// wrong chain) are reported back instead of silently vanishing.
type txResultMsg struct {
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// NetworkParams are the network's consensus/economic parameters, exposed
// read-only so clients (and operators) don't have to hardcode or guess
// values like the minimum acceptable fee.
type NetworkParams struct {
	ChainID       string `json:"chain_id"`
	MinFee        uint64 `json:"min_fee"`
	MaxTxPerBlock int    `json:"max_tx_per_block"`
	MaxBlockBytes int    `json:"max_block_bytes"`
	FinalityDepth uint64 `json:"finality_depth"`
	BlockSeconds  int    `json:"block_seconds"`
}
