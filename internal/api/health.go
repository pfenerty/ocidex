package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// HealthCheck handles liveness probes.
func (h *Handler) HealthCheck(_ context.Context, _ *struct{}) (*HealthCheckOutput, error) {
	out := &HealthCheckOutput{}
	out.Body.Status = "ok"
	return out, nil
}

// ReadinessCheck verifies the database is reachable.
func (h *Handler) ReadinessCheck(ctx context.Context, _ *struct{}) (*ReadinessCheckOutput, error) {
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	out := &ReadinessCheckOutput{}
	if err := h.db.Ping(pingCtx); err != nil {
		out.Body.Status = "unavailable"
		out.Body.Reason = "database unreachable"
		return out, huma.Error503ServiceUnavailable("database unreachable")
	}

	out.Body.Status = "ready"
	return out, nil
}

// APIVersion returns the API version.
func (h *Handler) APIVersion(_ context.Context, _ *struct{}) (*VersionOutput, error) {
	out := &VersionOutput{}
	out.Body.Version = "v1"
	return out, nil
}
