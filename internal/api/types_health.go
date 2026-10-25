package api

import "time"

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

// HealthCheckOutput is the response for GET /health.
type HealthCheckOutput struct {
	Body struct {
		Status string `json:"status" example:"ok" doc:"Health status"`
	}
}

// ReadinessCheckOutput is the response for GET /ready.
type ReadinessCheckOutput struct {
	Body struct {
		Status string `json:"status" example:"ready" doc:"Readiness status"`
		Reason string `json:"reason,omitempty" doc:"Reason for unavailability"`
	}
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

// VersionOutput is the response for GET /api/v1/.
type VersionOutput struct {
	Body struct {
		Version string `json:"version" example:"v1" doc:"API version"`
		Build   string `json:"build" example:"v1.0.0" doc:"Version of the running server build: a release tag, a Go module version, or 'dev'"`
		Commit  string `json:"commit" doc:"VCS revision the server was built from, or 'unknown'"`
		BuiltAt string `json:"builtAt" doc:"When the server was built, or 'unknown'"`
		// VulnDBBuiltAt dates the advisories behind every vulnerability count,
		// which is what a bug report about a missing CVE needs to know.
		VulnDBBuiltAt *time.Time `json:"vulnDbBuiltAt,omitempty" doc:"Build time of the vulnerability database the stored matches come from"`
	}
}
