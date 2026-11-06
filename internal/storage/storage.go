package storage

import (
	"context"
	"errors"

	"github.com/chesnokov-an/SafeBoardGo2026/internal/threat"
)

var (
	ErrNotFound      = errors.New("threat not found")
	ErrAlreadyExists = errors.New("threat already exists")
)

type Store interface {
	Create(ctx context.Context, t threat.Threat) error
	Get(ctx context.Context, md5 string) (threat.Threat, error)
	Replace(ctx context.Context, t threat.Threat) error
}
