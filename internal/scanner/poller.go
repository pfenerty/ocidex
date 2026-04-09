package scanner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// Poller periodically triggers catalog walks for poll-enabled registries.
type Poller struct {
	registrySvc  service.RegistryService
	submitter    Submitter
	digestLister DigestLister
	logger       *slog.Logger
	wg           sync.WaitGroup
}

// NewPoller constructs a Poller. The digestLister is used to skip re-scanning
// known digests; pass nil to disable dedup.
func NewPoller(registrySvc service.RegistryService, submitter Submitter, digestLister DigestLister, logger *slog.Logger) *Poller {
	return &Poller{
		registrySvc:  registrySvc,
		submitter:    submitter,
		digestLister: digestLister,
		logger:       logger,
	}
}

// Run ticks every minute and triggers catalog walks for due registries.
// Blocks until ctx is cancelled, then waits for in-flight walks to finish.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.poll(ctx)
		case <-ctx.Done():
			p.wg.Wait()
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
		p.wg.Add(1)
		go func(r service.Registry) { //nolint:gosec
			defer p.wg.Done()
			walkCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
			defer cancel()
			known := FetchKnownDigests(walkCtx, p.digestLister, r.ID)
			queued, err := WalkRegistry(walkCtx, r, p.submitter, known, p.logger)
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
