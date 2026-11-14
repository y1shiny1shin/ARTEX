package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store is a tiny single-user persistent state file. P0 deliberately avoids a
// database dependency: the state is small, writes are infrequent, and the file
// is easy to back up. The interface is designed so it can be replaced by SQLite
// or Postgres later without touching the HTTP layer.
type Store struct {
	mu    sync.Mutex
	path  string
	state State
}

type State struct {
	Devices       map[string]Device       `json:"devices"`
	Messages      []Message               `json:"messages"`
	Confirmations map[string]Confirmation `json:"confirmations"`
	Audit         []Audit                 `json:"audit"`
	NextMessageID int64                   `json:"next_message_id"`
	NextAuditID   int64                   `json:"next_audit_id"`
}

type Device struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"token_hash"`
	CreatedAt time.Time  `json:"created_at"`
	LastSeen  time.Time  `json:"last_seen"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type Message struct {
	ID        int64     `json:"id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Confirmation struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"device_id"`
	Capability string    `json:"capability"`
	Input      string    `json:"input"`
	Summary    string    `json:"summary"`
	State      string    `json:"state"` // pending | approved | rejected | expired | done | failed
	Result     string    `json:"result,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Audit struct {
	ID          int64     `json:"id"`
	DeviceID    string    `json:"device_id"`
	Action      string    `json:"action"`
	InputDigest string    `json:"input_digest"`
	Result      string    `json:"result"`
	CreatedAt   time.Time `json:"created_at"`
}

var ErrNotFound = errors.New("not found")

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path, state: State{
		Devices:       map[string]Device{},
		Confirmations: map[string]Confirmation{},
	}}
	raw, err := os.ReadFile(path)
	if err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.state); err != nil {
			return nil, fmt.Errorf("parse state: %w", err)
		}
	}
	if s.state.Devices == nil {
		s.state.Devices = map[string]Device{}
	}
	if s.state.Confirmations == nil {
		s.state.Confirmations = map[string]Confirmation{}
	}
	return s, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) CreateDevice(d Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Devices[d.ID]; ok {
		return fmt.Errorf("device %s already exists", d.ID)
	}
	s.state.Devices[d.ID] = d
	return s.saveLocked()
}

func (s *Store) DeviceByTokenHash(hash string) (Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.state.Devices {
		if d.TokenHash == hash {
			return d, true
		}
	}
	return Device{}, false
}

func (s *Store) TouchDevice(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.state.Devices[id]; ok {
		d.LastSeen = time.Now().UTC()
		s.state.Devices[id] = d
		_ = s.saveLocked()
	}
}

func (s *Store) RevokeDevice(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.state.Devices[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	d.RevokedAt = &now
	s.state.Devices[id] = d
	return s.saveLocked()
}

func (s *Store) AppendMessage(role, content string) Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.NextMessageID++
	m := Message{ID: s.state.NextMessageID, Role: role, Content: content, CreatedAt: time.Now().UTC()}
	s.state.Messages = append(s.state.Messages, m)
	if len(s.state.Messages) > 500 {
		s.state.Messages = s.state.Messages[len(s.state.Messages)-500:]
	}
	_ = s.saveLocked()
	return m
}

func (s *Store) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, len(s.state.Messages))
	copy(out, s.state.Messages)
	return out
}

func (s *Store) CreateConfirmation(c Confirmation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Confirmations[c.ID] = c
	return s.saveLocked()
}

func (s *Store) GetConfirmation(id string) (Confirmation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.Confirmations[id]
	return c, ok
}

func (s *Store) ListConfirmations() []Confirmation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Confirmation, 0, len(s.state.Confirmations))
	for _, c := range s.state.Confirmations {
		out = append(out, c)
	}
	return out
}

func (s *Store) ResolveConfirmation(id, state, result string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.state.Confirmations[id]
	if !ok {
		return ErrNotFound
	}
	c.State = state
	c.Result = result
	s.state.Confirmations[id] = c
	return s.saveLocked()
}

func (s *Store) AppendAudit(deviceID, action, inputDigest, result string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.NextAuditID++
	s.state.Audit = append(s.state.Audit, Audit{
		ID: s.state.NextAuditID, DeviceID: deviceID, Action: action,
		InputDigest: inputDigest, Result: result, CreatedAt: time.Now().UTC(),
	})
	if len(s.state.Audit) > 2000 {
		s.state.Audit = s.state.Audit[len(s.state.Audit)-2000:]
	}
	_ = s.saveLocked()
}

func (s *Store) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Audit, len(s.state.Audit))
	copy(out, s.state.Audit)
	return out
}
