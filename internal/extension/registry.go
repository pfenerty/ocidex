package extension

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/pfenerty/ocidex/internal/event"
)

// Manager manages the lifecycle of all registered extensions.
type Manager struct {
	bus        *event.Bus
	logger     *slog.Logger
	extensions []Extension
}

// NewManager creates a new extension manager.
func NewManager(bus *event.Bus, logger *slog.Logger) *Manager {
	return &Manager{bus: bus, logger: logger}
}

// Register adds an extension to the manager. Must be called before InitAll.
func (r *Manager) Register(ext Extension) {
	r.extensions = append(r.extensions, ext)
}

// InitAll calls Init on every registered extension in registration order.
// Fail-fast: the first Init error aborts startup.
func (r *Manager) InitAll() error {
	for _, ext := range r.extensions {
		r.logger.Info("initializing extension", "extension", ext.Name())
		if err := ext.Init(r.bus); err != nil {
			return fmt.Errorf("initializing extension %q: %w", ext.Name(), err)
		}
	}
	return nil
}

// StartAll calls Start on every registered extension in registration order.
func (r *Manager) StartAll(ctx context.Context) error {
	for _, ext := range r.extensions {
		r.logger.Info("starting extension", "extension", ext.Name())
		if err := ext.Start(ctx); err != nil {
			return fmt.Errorf("starting extension %q: %w", ext.Name(), err)
		}
	}
	return nil
}

// StopAll calls Stop on every registered extension in reverse registration order.
// All extensions are stopped even if one returns an error; the first error is returned.
func (r *Manager) StopAll() error {
	var firstErr error
	for i := len(r.extensions) - 1; i >= 0; i-- {
		ext := r.extensions[i]
		r.logger.Info("stopping extension", "extension", ext.Name())
		if err := ext.Stop(); err != nil {
			r.logger.Error("extension stop failed", "extension", ext.Name(), "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("stopping extension %q: %w", ext.Name(), err)
			}
		}
	}
	return firstErr
}
