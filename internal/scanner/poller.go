package scanner

import (
	"context"
	"log/slog"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// Poller periodically triggers catalog walks for poll-enabled registries.
type Poller struct {
	registrySvc service.RegistryService
	submitter   Submitter
	logger      *slog.Logger
}

// NewPoller constructs a Poller.
func NewPoller(registrySvc service.RegistryService, submitter Submitter, logger *slog.Logger) *Poller {
	return &Poller{
		registrySvc: registrySvc,
		submitter:   submitter,
		logger:      logger,
	}
}

// Run ticks every minute and triggers catalog walks for due registries.
// Blocks until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.poll(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	regs, err := p.registrySvc.ListPollable(ctx)
	if err != nil {
		p.logger.Error("poller: listing pollable registries", "err", err)
		return
	}
	now := time.Now()
	for _, reg := range regs {
		if !isDue(reg, now) {
			continue
		}
		// Mark polled before launching to prevent duplicate concurrent scans.
		if _, err := p.registrySvc.MarkPolled(ctx, reg.ID); err != nil {
			p.logger.Error("poller: marking registry polled", "registry", reg.Name, "err", err)
			continue
		}
		go func(r service.Registry) { //nolint:gosec
			walkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			queued, err := WalkRegistry(walkCtx, r, p.submitter, p.logger)
			if err != nil {
				p.logger.Error("poller: catalog walk failed", "registry", r.Name, "err", err)
				return
			}
			p.logger.Info("poller: catalog walk complete", "registry", r.Name, "queued", queued)
		}(reg)
	}
}

// isDue returns true if the registry has never been polled or its interval has elapsed.
func isDue(reg service.Registry, now time.Time) bool {
	if reg.LastPolledAt == nil {
		return true
	}
	return now.Sub(*reg.LastPolledAt) >= time.Duration(reg.PollIntervalMinutes)*time.Minute
}
