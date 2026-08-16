package api

import "github.com/pfenerty/ocidex/internal/service"

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

// RegistryResponse is the public representation of a configured OCI registry.
type RegistryResponse struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Type                string   `json:"type"`
	URL                 string   `json:"url"`
	Insecure            bool     `json:"insecure"`
	HasSecret           bool     `json:"has_secret"`
	HasAuth             bool     `json:"has_auth"`
	Enabled             bool     `json:"enabled"`
	WebhookURL          string   `json:"webhook_url"`
	Repositories        []string `json:"repositories" doc:"Explicit repositories to walk; overrides catalog discovery when non-empty"`
	RepositoryPatterns  []string `json:"repository_patterns" doc:"Glob patterns for repositories to ingest; empty = all"`
	TagPatterns         []string `json:"tag_patterns" doc:"Glob patterns or 'semver' for tags to ingest; empty = all"`
	ScanMode            string   `json:"scan_mode"`
	PollIntervalMinutes int      `json:"poll_interval_minutes"`
	LastPolledAt        *string  `json:"last_polled_at,omitempty"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
	Visibility          string   `json:"visibility" doc:"Registry visibility: public or private"`
	OwnerID             *string  `json:"owner_id,omitempty" doc:"UUID of the registry owner"`
	OwnerUsername       *string  `json:"owner_username,omitempty" doc:"GitHub username of the registry owner"`
	IncludeUntagged     bool     `json:"include_untagged" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
	VerificationMode    string   `json:"verification_mode" enum:"none,public_key,keyless" doc:"Signature verification mode"`
	TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key for public_key verification mode"`
	TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required for keyless verification mode"`
	TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required for keyless verification mode"`
	ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration (e.g. kubernetes); absent when managed through this API"`
	ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system, e.g. '<namespace>/<name>' of the OCIRegistry resource"`
}

// ListRegistriesInput is the request for GET /api/v1/registries.
type ListRegistriesInput struct {
	PaginationParams
}

// ListMyRegistriesInput is the request for GET /api/v1/users/me/registries.
type ListMyRegistriesInput struct {
	PaginationParams
}

// ListRegistriesOutput is the response for GET /api/v1/registries.
type ListRegistriesOutput struct {
	Body struct {
		Data       []RegistryResponse `json:"data"`
		Pagination PaginationMeta     `json:"pagination"`
	}
}

// GetRegistryInput is the request for GET /api/v1/registries/{id}.
type GetRegistryInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// GetRegistryOutput is the response for GET /api/v1/registries/{id}.
type GetRegistryOutput struct {
	Body RegistryResponse
}

// GetRegistryByNameInput is the request for GET /api/v1/registries/by-name/{name}.
type GetRegistryByNameInput struct {
	Name string `path:"name" doc:"Registry name"`
}

// GetRegistryByNameOutput is the response for GET /api/v1/registries/by-name/{name}.
type GetRegistryByNameOutput struct {
	Body RegistryResponse
}

// CreateRegistryInput is the request for POST /api/v1/registries.
type CreateRegistryInput struct {
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable registry name"`
		Namespace           string   `json:"namespace,omitempty" maxLength:"100" doc:"Namespace to create the registry in, created on first use; omit to give the registry a namespace of its own named after it"`
		Type                string   `json:"type" enum:"zot,harbor,docker,generic,ghcr" doc:"Registry type"`
		URL                 string   `json:"url" minLength:"1" doc:"Registry address (e.g. zot:5000)"`
		Insecure            bool     `json:"insecure" doc:"Allow HTTP (non-TLS) connections"`
		WebhookSecret       *string  `json:"webhook_secret,omitempty" doc:"Bearer token required on incoming webhooks; omit to disable auth"`
		AuthUsername        *string  `json:"auth_username,omitempty" doc:"Username for registry authentication; omit for anonymous access"`
		AuthToken           *string  `json:"auth_token,omitempty" doc:"Token or PAT for registry authentication; omit for anonymous access"`
		Repositories        []string `json:"repositories,omitempty" doc:"Explicit repositories to walk; bypasses /v2/_catalog discovery when non-empty"`
		RepositoryPatterns  []string `json:"repository_patterns,omitempty" doc:"Glob patterns for repositories to ingest; empty = all"`
		TagPatterns         []string `json:"tag_patterns,omitempty" doc:"Glob patterns or 'semver' for tags to ingest; empty = all"`
		ScanMode            string   `json:"scan_mode,omitempty" enum:"webhook,poll,both" doc:"Scanning mode"`
		PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty" minimum:"1" doc:"Minutes between polls"`
		Visibility          string   `json:"visibility,omitempty" enum:"public,private" default:"public" doc:"Registry visibility"`
		IncludeUntagged     bool     `json:"include_untagged,omitempty" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
		VerificationMode    string   `json:"verification_mode,omitempty" enum:"none,public_key,keyless" doc:"Signature verification mode; defaults to none"`
		TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key; required when verification_mode is public_key"`
		TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required when verification_mode is keyless"`
		TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required when verification_mode is keyless"`
		ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration (e.g. kubernetes); set by that system's controller, not by hand"`
		ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system, e.g. '<namespace>/<name>' of the OCIRegistry resource"`
	}
}

// CreateRegistryResponseBody extends RegistryResponse with the generated webhook secret,
// which is returned once on creation and never again.
type CreateRegistryResponseBody struct {
	RegistryResponse
	WebhookSecret string `json:"webhook_secret,omitempty" doc:"Generated webhook secret — shown once only. Store it securely; it cannot be retrieved again."`
}

// CreateRegistryOutput is the response for POST /api/v1/registries.
type CreateRegistryOutput struct {
	Body CreateRegistryResponseBody
}

// RegenerateWebhookSecretInput is the request for POST /api/v1/registries/{id}/webhook-secret.
type RegenerateWebhookSecretInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// RegenerateWebhookSecretOutput is the response for POST /api/v1/registries/{id}/webhook-secret.
type RegenerateWebhookSecretOutput struct {
	Body struct {
		WebhookSecret string `json:"webhook_secret" doc:"New webhook secret — shown once only. The previous secret is immediately invalidated."`
	}
}

// UpdateRegistryInput is the request for PATCH /api/v1/registries/{id}.
type UpdateRegistryInput struct {
	ID   string `path:"id" doc:"Registry UUID" format:"uuid"`
	Body struct {
		Name                string   `json:"name" minLength:"1" maxLength:"100"`
		Type                string   `json:"type" enum:"zot,harbor,docker,generic,ghcr"`
		URL                 string   `json:"url" minLength:"1"`
		Insecure            bool     `json:"insecure"`
		AuthUsername        *string  `json:"auth_username,omitempty"`
		AuthToken           *string  `json:"auth_token,omitempty"`
		Enabled             bool     `json:"enabled"`
		Repositories        []string `json:"repositories,omitempty"`
		RepositoryPatterns  []string `json:"repository_patterns,omitempty"`
		TagPatterns         []string `json:"tag_patterns,omitempty"`
		ScanMode            string   `json:"scan_mode,omitempty" enum:"webhook,poll,both" doc:"Scanning mode"`
		PollIntervalMinutes int      `json:"poll_interval_minutes,omitempty" minimum:"1" doc:"Minutes between polls"`
		Visibility          string   `json:"visibility,omitempty" enum:"public,private" doc:"Registry visibility"`
		IncludeUntagged     bool     `json:"include_untagged,omitempty" doc:"Scan untagged manifests via registry-specific APIs (supported: zot, harbor, ghcr)"`
		VerificationMode    string   `json:"verification_mode,omitempty" enum:"none,public_key,keyless" doc:"Signature verification mode; defaults to none"`
		TrustPublicKey      *string  `json:"trust_public_key,omitempty" doc:"PEM-encoded EC public key; required when verification_mode is public_key"`
		TrustIdentity       *string  `json:"trust_identity,omitempty" doc:"Regex matched against the Fulcio certificate SAN; required when verification_mode is keyless"`
		TrustIssuer         *string  `json:"trust_issuer,omitempty" doc:"Expected OIDC issuer URL; required when verification_mode is keyless"`
		ManagedBy           *string  `json:"managed_by,omitempty" doc:"External system that owns this registry's configuration; omit to leave the existing marker untouched"`
		ManagedRef          *string  `json:"managed_ref,omitempty" doc:"Identifier within the managing system; omit to leave the existing value untouched"`
	}
}

// ScanRegistryInput is the request for POST /api/v1/registries/{id}/scan.
type ScanRegistryInput struct {
	ID    string `path:"id" doc:"Registry UUID" format:"uuid"`
	Force bool   `query:"force" doc:"Re-scan every image, including digests already ingested. Default false: already-scanned digests are skipped."`
}

// ScanRegistryOutput is the response for POST /api/v1/registries/{id}/scan.
type ScanRegistryOutput struct {
	Body struct {
		Message string `json:"message" doc:"Confirmation that ad-hoc scan has been initiated"`
	}
}

// UpdateRegistryOutput is the response for PUT /api/v1/registries/{id}.
type UpdateRegistryOutput struct {
	Body RegistryResponse
}

// DeleteRegistryInput is the request for DELETE /api/v1/registries/{id}.
type DeleteRegistryInput struct {
	ID string `path:"id" doc:"Registry UUID" format:"uuid"`
}

// TestRegistryConnectionInput is the request for POST /api/v1/registries/test-connection.
type TestRegistryConnectionInput struct {
	Body struct {
		URL          string  `json:"url" minLength:"1" doc:"Registry address (e.g. zot:5000)"`
		Insecure     bool    `json:"insecure" doc:"Use HTTP instead of HTTPS"`
		AuthUsername *string `json:"auth_username,omitempty" doc:"Username for registry authentication"`
		AuthToken    *string `json:"auth_token,omitempty" doc:"Token or PAT for registry authentication"`
	}
}

// TestRegistryConnectionOutput is the response for POST /api/v1/registries/test-connection.
type TestRegistryConnectionOutput struct {
	Body struct {
		Reachable bool   `json:"reachable" doc:"Whether the registry responded"`
		Message   string `json:"message" doc:"Human-readable result (e.g. HTTP 200 or error text)"`
	}
}

// RegistryWebhookInput is the request for POST /api/v1/registries/{id}/webhook.
type RegistryWebhookInput struct {
	ID            string `path:"id" doc:"Registry UUID" format:"uuid"`
	Authorization string `header:"Authorization"`
	Body          struct {
		Name      string `json:"name"`
		Reference string `json:"reference"`
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
		Manifest  string `json:"manifest"`
	}
}

// GetRegistryTrustSummaryOutput is the response for GET /api/v1/registries/trust-summary.
// Admin-only: aggregates across all registries, bypassing per-registry visibility.
type GetRegistryTrustSummaryOutput struct {
	Body struct {
		Data []service.RegistryTrustCount `json:"data"`
	}
}

// ListRecentDriftInput is the request for GET /api/v1/registries/drift-feed.
type ListRecentDriftInput struct {
	CursorParams
}

// ListMyDriftFeedInput is the request for GET /api/v1/users/me/drift-feed.
type ListMyDriftFeedInput struct {
	CursorParams
}

// ListRecentDriftOutput is the response for GET /api/v1/registries/drift-feed.
// Admin-only: aggregates across all registries, bypassing per-registry visibility.
type ListRecentDriftOutput struct {
	Body struct {
		Data       []service.RecentDriftEntry `json:"data"`
		Pagination CursorMeta                 `json:"pagination"`
	}
}
