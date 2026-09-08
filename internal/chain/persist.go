package chain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"claude-blockchain/internal/types"
)

// openLog opens (creating if necessary) the append-only block log at path,
// replays any blocks already in it through normal AddBlock validation to
// rebuild state, and leaves the file open for future appends.
//
// Replaying through AddBlock (rather than trusting the file blindly) means
// a corrupted or tampered log is rejected the same way a bad block from the
// network would be, instead of silently poisoning this node's state.
func (c *Chain) openLog(path string) error {
	if f, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var block types.Block
			if err := json.Unmarshal(line, &block); err != nil {
				f.Close()
				return fmt.Errorf("replay %s: corrupt entry: %w", path, err)
			}
			if err := c.addBlockNoLog(block); err != nil {
				f.Close()
				return fmt.Errorf("replay %s: %w", path, err)
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return fmt.Errorf("replay %s: %w", path, err)
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return err
	}

	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	c.logFile = out
	return nil
}

// addBlockNoLog runs the same validation/apply path as AddBlock but without
// touching c.logFile, used while replaying the log itself.
func (c *Chain) addBlockNoLog(block types.Block) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.applyBlockLocked(block)
}

func (c *Chain) appendLog(block types.Block) error {
	data, err := json.Marshal(block)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.logFile.Write(data)
	if err != nil {
		return err
	}
	return c.logFile.Sync()
}

// rewriteLog atomically rewrites the block log to match c.blocks (used
// after a chain replacement during sync). Caller must hold c.mu.
func (c *Chain) rewriteLog() error {
	name := c.logFile.Name()
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, block := range c.blocks {
		data, err := json.Marshal(block)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := w.Write(append(data, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	c.logFile.Close()
	out, err := os.OpenFile(name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	c.logFile = out
	return nil
}

// Close flushes and closes the persisted block log, if any.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.logFile != nil {
		return c.logFile.Close()
	}
	return nil
}
