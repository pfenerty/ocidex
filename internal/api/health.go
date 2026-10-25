package api

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/version"
)

// ContractVersion is the version of the /api/v1 contract, published as the OpenAPI
// info.version (ADR-052). It is deliberately not the build version, so specgen output
// is identical for every build. Bump the minor for an additive change; the major moves
// only together with a new /api/vN prefix. The running build's version is reported by
// GET /api/v1/ instead.
const ContractVersion = "1.0.0"

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

// APIVersion returns the API version and the version of the running server build.
func (h *Handler) APIVersion(ctx context.Context, _ *struct{}) (*VersionOutput, error) {
	out := &VersionOutput{}
	out.Body.Version = "v1"
	out.Body.Build, out.Body.Commit, out.Body.BuiltAt = version.Info()
	// The database age is best-effort: About still says which build is
	// running when the database cannot be read.
	if h.searchService != nil {
		if built, err := h.searchService.VulnDBBuiltAt(ctx); err == nil {
			out.Body.VulnDBBuiltAt = built
		}
	}
	return out, nil
}
