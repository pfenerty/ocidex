package api

import (
	"time"

	"github.com/pfenerty/ocidex/internal/service"
)

// ---------------------------------------------------------------------------
// Auth — Me
// ---------------------------------------------------------------------------

// MeOutput is the response for GET /api/v1/users/me.
type MeOutput struct {
	Body struct {
		ID             string `json:"id" doc:"User UUID"`
		GitHubUsername string `json:"github_username" doc:"GitHub login"`
		Role           string `json:"role" doc:"User role: admin, member, or viewer"`
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
		Name  string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable label for this key"`
		Scope string `json:"scope,omitempty" enum:"read,read-write" default:"read-write" doc:"Key scope: read (GET only) or read-write (full access)"`
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
	ID         string     `json:"id" doc:"Key UUID"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix" doc:"First 8 characters of the key"`
	Scope      string     `json:"scope" enum:"read,read-write" doc:"Key scope"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
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
