package storage

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

// Memory is a concurrency-safe in-memory Store.
type Memory struct {
	mu    sync.RWMutex
	items map[string]threat.Threat
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		mu:    sync.RWMutex{},
		items: make(map[string]threat.Threat),
	}
}

// Create implements Store.
func (m *Memory) Create(ctx context.Context, t threat.Threat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.items[t.MD5]
	if ok {
		return ErrAlreadyExists
	}
	m.items[t.MD5] = cloneThreat(t)
	return nil
}

// Get implements Store.
func (m *Memory) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.items[md5]
	if !ok {
		return threat.Threat{}, fmt.Errorf("%w: md5 %s", ErrNotFound, md5)
	}
	return cloneThreat(t), nil
}

// Replace implements Store.
func (m *Memory) Replace(ctx context.Context, t threat.Threat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[t.MD5]; !ok {
		return fmt.Errorf("%w: md5 %s", ErrNotFound, t.MD5)
	}
	m.items[t.MD5] = cloneThreat(t)
	return nil
}

// cloneThreat returns a deep copy of t so callers cannot mutate stored data.
func cloneThreat(t threat.Threat) threat.Threat {
	clone := t
	if t.Tags != nil {
		clone.Tags = slices.Clone(t.Tags)
	}
	if t.FirstSeen != nil {
		firstSeen := *t.FirstSeen
		clone.FirstSeen = &firstSeen
	}
	if t.LastSeen != nil {
		lastSeen := *t.LastSeen
		clone.LastSeen = &lastSeen
	}
	return clone
}
