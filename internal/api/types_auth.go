package api

import (
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Auth — Me
// ---------------------------------------------------------------------------

// MyMembership is one of the caller's own namespace_member rows.
//
// It carries the namespace ID and the role and nothing else: it exists so a
// client can tell what kind of user is signed in — mostly security, mostly
// developer, or answerable for a namespace — and emphasise accordingly. It is
// not an authorization input. Every endpoint re-derives the caller's grants
// server-side on each request (ADR-046 M1), so a client that lied about this
// list would change nothing but its own layout.
type MyMembership struct {
	NamespaceID string `json:"namespace_id" doc:"Namespace UUID"`
	Role        string `json:"role" enum:"owner,maintainer,security,developer,viewer" doc:"The caller's role in that namespace"`
}

// MeOutput is the response for GET /api/v1/users/me.
type MeOutput struct {
	Body struct {
		ID             string         `json:"id" doc:"User UUID"`
		GitHubUsername string         `json:"github_username" doc:"GitHub login"`
		Role           string         `json:"role" doc:"User role: admin, member, or viewer"`
		Memberships    []MyMembership `json:"memberships" doc:"The caller's namespace memberships, for UI emphasis only"`
	}
}

// ListMyActivityInput is the request for GET /api/v1/users/me/activity.
type ListMyActivityInput struct {
	CursorParams
}

// ListMyActivityOutput is the response for GET /api/v1/users/me/activity.
type ListMyActivityOutput struct {
	Body struct {
		Data       []service.ActivityEntry `json:"data"`
		Pagination CursorMeta              `json:"pagination"`
	}
}

// ---------------------------------------------------------------------------
// Auth — Watchlist
// ---------------------------------------------------------------------------

// ListMyWatchesInput is the request for GET /api/v1/users/me/watches.
type ListMyWatchesInput struct {
	CursorParams
}

// ListMyWatchesOutput is the response for GET /api/v1/users/me/watches.
type ListMyWatchesOutput struct {
	Body struct {
		Data       []service.WatchEntry `json:"data"`
		Pagination CursorMeta           `json:"pagination"`
	}
}

type ListMyWatchFeedInput struct{ CursorParams }

type ListMyWatchFeedOutput struct {
	Body struct {
		Data       []service.WatchEvent `json:"data"`
		Pagination CursorMeta           `json:"pagination"`
	}
}

// WatchArtifactInput identifies the artifact to watch or unwatch. It is shared
// by both verbs because a watch has no body — the pair (caller, artifact) is
// the whole resource.
type WatchArtifactInput struct {
	ArtifactID string `path:"artifact_id" format:"uuid" doc:"Artifact UUID"`
}

// ---------------------------------------------------------------------------
// Auth — API Keys
// ---------------------------------------------------------------------------

// CreateAPIKeyInput is the request for POST /api/v1/auth/keys.
type CreateAPIKeyInput struct {
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable label for this key"`
		// Capabilities is a ceiling, not a grant: the key can never do more
		// than its owner's live namespace roles allow. Omitting it asks for
		// every capability, which resolves to exactly what the owner can do.
		Capabilities []string `json:"capabilities,omitempty" enum:"read_private,ingest,trigger_scan,push_inventory,delete_artifact,manage_source,manage_cluster,read_secret,manage_member,delete_namespace" doc:"Capabilities this key may exercise, intersected with the owner's live namespace roles. Empty means all of them."`
	}
}

// CreateAPIKeyOutput is the response for POST /api/v1/auth/keys.
type CreateAPIKeyOutput struct {
	Body struct {
		Key string `json:"key" doc:"Full API key — shown once, store securely"`
	}
}

// KeyMetaResponse is the display-safe API key representation.
type KeyMetaResponse struct {
	ID           string     `json:"id" doc:"Key UUID"`
	Name         string     `json:"name"`
	Prefix       string     `json:"prefix" doc:"First 8 characters of the key"`
	Capabilities []string   `json:"capabilities" doc:"Capabilities this key may exercise, before intersection with the owner's live namespace roles"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// ListAPIKeysOutput is the response for GET /api/v1/auth/keys.
type ListAPIKeysOutput struct {
	Body struct {
		Keys []KeyMetaResponse `json:"keys"`
	}
}

// DeleteAPIKeyInput is the request for DELETE /api/v1/auth/keys/{id}.
type DeleteAPIKeyInput struct {
	ID string `path:"id" doc:"Key UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Auth — Users (admin)
// ---------------------------------------------------------------------------

// UserResponse is the public representation of a user.
type UserResponse struct {
	ID             string `json:"id"`
	GitHubUsername string `json:"github_username"`
	Role           string `json:"role"`
}

// ListUsersOutput is the response for GET /api/v1/users.
type ListUsersOutput struct {
	Body struct {
		Users []UserResponse `json:"users"`
	}
}

// UpdateUserRoleInput is the request for PATCH /api/v1/users/{id}/role.
type UpdateUserRoleInput struct {
	ID   string `path:"id" doc:"User UUID" format:"uuid"`
	Body struct {
		Role string `json:"role" enum:"admin,member,viewer" doc:"New role"`
	}
}

// UpdateUserRoleOutput is the response for PATCH /api/v1/users/{id}/role.
type UpdateUserRoleOutput struct {
	Body UserResponse
}
