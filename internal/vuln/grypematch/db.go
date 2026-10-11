package grypematch

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/anchore/grype/grype/vulnerability"
)

// opener installs-or-updates and opens a database; LoadDB in production.
type opener func(update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error)

// DB owns the lifecycle of the on-disk grype database and the Matcher over it.
// It is not safe for concurrent use: the vuln-worker drives it from its single
// leader-elected loop, so Refresh and matching never overlap.
type DB struct {
	open    opener
	logger  *slog.Logger
	matcher *Matcher
	built   time.Time
}

// NewDB returns a DB that installs and updates the database described by cfg.
func NewDB(cfg DBConfig, logger *slog.Logger) *DB {
	if logger == nil {
		logger = slog.Default()
	}
	return &DB{
		open: func(update bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			return LoadDB(cfg, update)
		},
		logger: logger,
	}
}

// NewFixedDB returns a DB over an already-open provider with a fixed build time;
// Refresh never downloads. For integration tests and offline use. The caller
// keeps ownership of provider: the DB never closes it.
func NewFixedDB(provider vulnerability.Provider, built time.Time, logger *slog.Logger) *DB {
	if logger == nil {
		logger = slog.Default()
	}
	return &DB{
		open: func(bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
			// Each Refresh "reopens" the same provider and closes the redundant
			// handle; the wrapper keeps that from closing the one in use.
			return keepOpen{provider}, &vulnerability.ProviderStatus{Built: built}, nil
		},
		logger: logger,
	}
}

// keepOpen is a provider whose Close is a no-op.
type keepOpen struct{ vulnerability.Provider }

func (keepOpen) Close() error { return nil }

// Refresh checks for a newer database, installs it if there is one, and reopens
// the matcher over whatever is installed. changed reports whether the build now
// open differs from the one open before — the signal to re-match stored SBOMs.
//
// On failure the previously opened matcher (if any) stays in use; a stale but
// valid database beats none. grype itself rejects a database older than
// DBConfig.MaxAge, so staleness is bounded.
func (d *DB) Refresh() (changed bool, err error) {
	provider, status, err := d.open(true)
	if err != nil {
		return false, fmt.Errorf("loading grype db: %w", err)
	}
	if d.matcher != nil && status.Built.Equal(d.built) {
		_ = provider.Close()
		return false, nil
	}
	old := d.matcher
	d.matcher = NewMatcher(provider)
	prev := d.built
	d.built = status.Built
	if old != nil {
		_ = old.Close()
	}
	d.logger.Info("grype db opened", "built", d.built, "previous", prev, "schema", status.SchemaVersion)
	return true, nil
}

// Matcher returns the matcher over the open database and that database's build
// time. It is nil until the first successful Refresh.
func (d *DB) Matcher() (*Matcher, time.Time) { return d.matcher, d.built }

// Close releases the open database.
func (d *DB) Close() error {
	if d.matcher == nil {
		return nil
	}
	return d.matcher.Close()
}
