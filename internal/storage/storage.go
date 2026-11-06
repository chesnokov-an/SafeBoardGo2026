// Package storage defines persistence contracts and in-memory storage for
// threat records.
package storage

import (
	"context"
	"errors"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

// Errors returned by Store implementations.
var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

// Store persists threat records keyed by MD5.
type Store interface {
	// Create stores t and returns ErrAlreadyExists if its MD5 is already taken.
	Create(ctx context.Context, t threat.Threat) error
	// Get returns the record with the given MD5 or ErrNotFound.
	Get(ctx context.Context, md5 string) (threat.Threat, error)
	// Replace overwrites the record with t.MD5 or returns ErrNotFound.
	Replace(ctx context.Context, t threat.Threat) error
}
