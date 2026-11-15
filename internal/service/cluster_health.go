package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pfenerty/ocidex/internal/metrics"
	"github.com/pfenerty/ocidex/internal/repository"
)

// Agent health states (ocidex-70eo.4). Exhaustive: every cluster is in one.
const (
	// HealthNeverReported: no push has been accepted, and none rejected.
	HealthNeverReported = "never_reported"
	// HealthHealthy: the last push was accepted and is recent.
	HealthHealthy = "healthy"
	// HealthStale: the last accepted push is older than the agent's own
	// interval allows, and nothing has been rejected since — the agent is
	// down or cannot reach OCIDex.
	HealthStale = "stale"
	// HealthErroring: OCIDex is hearing from the agent and refusing it. The
	// reason says why.
	HealthErroring = "erroring"
	// HealthPaused: someone paused the cluster on purpose (ocidex-70eo.9).
	// It outranks the others: refusals and silence are both expected.
	HealthPaused = "paused"
)

// DefaultReportInterval is what staleness is judged against when the agent
// has not said its interval: the chart's default.
const DefaultReportInterval = 5 * time.Minute

// staleIntervals is how many missed reports make a cluster stale. Three, so
// one slow or failed push is not an alert.
const staleIntervals = 3

// keepPushes bounds the per-cluster push history.
const keepPushes = 50

// ClusterHealth is the derived agent state of a cluster.
type ClusterHealth struct {
	State  string
	Reason string
	// StaleAfter is how long after the last accepted push the cluster turns
	// stale; zero for a one-shot agent, which has no next push to miss.
	StaleAfter time.Duration
}

// ClusterPush is one recorded push attempt.
type ClusterPush struct {
	At           time.Time
	Accepted     bool
	Status       int
	Reason       string
	Workloads    *int32
	AgentVersion string
}

// PushAttempt is what a caller records about one push.
type PushAttempt struct {
	Accepted     bool
	Status       int
	Reason       string
	Workloads    *int32
	AgentVersion string
}

// Health derives the cluster's agent health at now.
func (c Cluster) Health(now time.Time) ClusterHealth {
	if c.PausedAt != nil {
		return ClusterHealth{State: HealthPaused, Reason: "Paused " + c.PausedAt.UTC().Format("2006-01-02 15:04 UTC") + ": snapshots are refused and the last inventory is kept."}
	}
	if c.LastPushErrorAt != nil && (c.LastSeenAt == nil || c.LastPushErrorAt.After(*c.LastSeenAt)) {
		return ClusterHealth{State: HealthErroring, Reason: c.LastPushError}
	}
	if c.LastSeenAt == nil {
		return ClusterHealth{State: HealthNeverReported, Reason: "No agent has pushed a snapshot yet."}
	}
	interval := DefaultReportInterval
	if c.Agent != nil && c.Agent.ReportIntervalSeconds != nil {
		if *c.Agent.ReportIntervalSeconds == 0 {
			return ClusterHealth{State: HealthHealthy, Reason: "One-shot agent: the last run was accepted."}
		}
		interval = time.Duration(*c.Agent.ReportIntervalSeconds) * time.Second
	}
	staleAfter := staleIntervals * interval
	if age := now.Sub(*c.LastSeenAt); age > staleAfter {
		return ClusterHealth{
			State:      HealthStale,
			Reason:     fmt.Sprintf("No snapshot for %s; the agent reports every %s.", shortDuration(age), shortDuration(interval)),
			StaleAfter: staleAfter,
		}
	}
	return ClusterHealth{State: HealthHealthy, StaleAfter: staleAfter}
}

// shortDuration renders a duration to the minute without Go's trailing zero
// units: 8h40m, 5m, 2h.
func shortDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	h, m := int(d/time.Hour), int((d%time.Hour)/time.Minute)
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	default:
		return fmt.Sprintf("%dh%dm", h, m)
	}
}

// RecordPush stores a push attempt and, for a rejection, marks the cluster as
// erroring with its reason. Unknown cluster ids are ignored.
func (s *clusterService) RecordPush(ctx context.Context, clusterID string, p PushAttempt) error {
	cid, err := parseUUID(clusterID)
	if err != nil {
		// Not a cluster id at all: nothing to record against, as for an
		// unknown one.
		return nil //nolint:nilerr // documented no-op
	}
	params := repository.RecordClusterPushParams{
		ClusterID:    cid,
		Accepted:     p.Accepted,
		Status:       int32(p.Status), //nolint:gosec // an HTTP status
		Reason:       p.Reason,
		AgentVersion: optText(p.AgentVersion),
	}
	if p.Workloads != nil {
		params.Workloads = pgtype.Int4{Int32: *p.Workloads, Valid: true}
	}
	n, err := s.repo.RecordClusterPush(ctx, params)
	if err != nil {
		return fmt.Errorf("recording push: %w", err)
	}
	if n == 0 {
		return nil
	}
	if err := s.repo.PruneClusterPushes(ctx, repository.PruneClusterPushesParams{ClusterID: cid, Keep: keepPushes}); err != nil {
		return fmt.Errorf("pruning push history: %w", err)
	}
	if !p.Accepted {
		if err := s.repo.MarkClusterPushError(ctx, repository.MarkClusterPushErrorParams{
			ID: cid, LastPushError: pgtype.Text{String: p.Reason, Valid: true},
		}); err != nil {
			return fmt.Errorf("marking push error: %w", err)
		}
	}
	return nil
}

// ListPushes returns the cluster's most recent push attempts, newest first.
func (s *clusterService) ListPushes(ctx context.Context, clusterID string, limit int32) ([]ClusterPush, error) {
	cid, err := parseUUID(clusterID)
	if err != nil {
		return nil, ErrNotFound
	}
	rows, err := s.repo.ListClusterPushes(ctx, repository.ListClusterPushesParams{ClusterID: cid, Max: limit})
	if err != nil {
		return nil, fmt.Errorf("listing pushes: %w", err)
	}
	out := make([]ClusterPush, len(rows))
	for i, r := range rows {
		p := ClusterPush{
			At:           r.At.Time,
			Accepted:     r.Accepted,
			Status:       int(r.Status),
			Reason:       r.Reason,
			AgentVersion: r.AgentVersion.String,
		}
		if r.Workloads.Valid {
			n := r.Workloads.Int32
			p.Workloads = &n
		}
		out[i] = p
	}
	return out, nil
}

// healthCacheTTL bounds how often a scrape lists clusters.
const healthCacheTTL = 30 * time.Second

// ObserveClusterHealth exports ocidex.cluster.health: one series per cluster,
// value 1, labelled with its state, so an alert can be written as
// `ocidex_cluster_health{state=~"stale|erroring"} == 1` and name the cluster.
func ObserveClusterHealth(mp metric.MeterProvider, svc ClusterService, logger *slog.Logger) (metric.Registration, error) {
	m := metrics.Meter(mp)
	gauge, err := m.Int64ObservableGauge("ocidex.cluster.health",
		metric.WithDescription("Agent health per registered cluster: 1 on the series whose state label is current."),
		metric.WithUnit("{cluster}"))
	if err != nil {
		return nil, err
	}
	var (
		mu     sync.Mutex
		last   []Cluster
		lastAt time.Time
	)
	return m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		mu.Lock()
		defer mu.Unlock()
		if last == nil || time.Since(lastAt) >= healthCacheTTL {
			cs, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
			if err != nil {
				logger.Warn("listing clusters for health metric", "err", err)
				return nil
			}
			last, lastAt = cs, time.Now()
		}
		now := time.Now()
		for _, c := range last {
			o.ObserveInt64(gauge, 1, metric.WithAttributes(
				attribute.String("cluster_id", c.ID),
				attribute.String("cluster", c.Name),
				attribute.String("namespace", c.NamespaceName),
				attribute.String("state", c.Health(now).State),
			))
		}
		return nil
	}, gauge)
}
