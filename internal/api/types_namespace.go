package api

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

// NamespaceResponse is a namespace as returned by the API. A namespace is the
// authorization anchor (ADR-039): ownership and visibility live here, not on
// the sources or registries beneath it.
type NamespaceResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Visibility    string  `json:"visibility" enum:"public,private" doc:"Namespace visibility: public or private"`
	OwnerID       *string `json:"owner_id,omitempty" doc:"UUID of the namespace owner"`
	OwnerUsername *string `json:"owner_username,omitempty" doc:"GitHub username of the namespace owner"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ListNamespacesInput is the request for GET /api/v1/namespaces.
type ListNamespacesInput struct{}

// ListMyNamespacesInput is the request for GET /api/v1/users/me/namespaces.
// It reuses ListNamespacesOutput: the projection is identical and only the row
// rule differs (ocidex-998g.2).
type ListMyNamespacesInput struct{}

// ListNamespacesOutput is the response for GET /api/v1/namespaces.
type ListNamespacesOutput struct {
	Body struct {
		Data []NamespaceResponse `json:"data"`
	}
}

// GetNamespaceInput is the request for GET /api/v1/namespaces/{id}.
type GetNamespaceInput struct {
	ID string `path:"id" doc:"Namespace UUID" format:"uuid"`
}

// GetNamespaceOutput is the response for GET /api/v1/namespaces/{id}.
type GetNamespaceOutput struct {
	Body NamespaceResponse
}

// GetNamespaceByNameInput is the request for GET /api/v1/namespaces/by-name/{name}.
type GetNamespaceByNameInput struct {
	Name string `path:"name" doc:"Namespace name"`
}

// GetNamespaceByNameOutput is the response for GET /api/v1/namespaces/by-name/{name}.
type GetNamespaceByNameOutput struct {
	Body NamespaceResponse
}

// CreateNamespaceInput is the request for POST /api/v1/namespaces.
type CreateNamespaceInput struct {
	Body struct {
		Name       string `json:"name" minLength:"1" maxLength:"100" doc:"Human-readable namespace name"`
		Visibility string `json:"visibility,omitempty" enum:"public,private" doc:"Namespace visibility; defaults to private"`
	}
}

// CreateNamespaceOutput is the response for POST /api/v1/namespaces.
type CreateNamespaceOutput struct {
	Body NamespaceResponse
}

// UpdateNamespaceInput is the request for PATCH /api/v1/namespaces/{id}.
type UpdateNamespaceInput struct {
	ID   string `path:"id" doc:"Namespace UUID" format:"uuid"`
	Body struct {
		Name       string `json:"name,omitempty" maxLength:"100" doc:"New namespace name; omit to keep the current one"`
		Visibility string `json:"visibility,omitempty" enum:"public,private" doc:"New visibility; omit to keep the current one"`
	}
}

// UpdateNamespaceOutput is the response for PATCH /api/v1/namespaces/{id}.
type UpdateNamespaceOutput struct {
	Body NamespaceResponse
}

// DeleteNamespaceInput is the request for DELETE /api/v1/namespaces/{id}.
type DeleteNamespaceInput struct {
	ID string `path:"id" doc:"Namespace UUID" format:"uuid"`
}

// ---------------------------------------------------------------------------
// Namespace members (ocidex-y0hg.7)
// ---------------------------------------------------------------------------

// NamespaceMemberResponse is one seat at a namespace. The username is joined in
// for display; user_id is the identifier the mutating routes take, because a
// GitHub username is a handle its owner can change.
type NamespaceMemberResponse struct {
	UserID    string   `json:"user_id" doc:"UUID of the member"`
	Username  string   `json:"username" doc:"GitHub username of the member"`
	Role      string   `json:"role" enum:"owner,maintainer,security,developer,viewer" doc:"The member's role in this namespace"`
	Caps      []string `json:"capabilities" doc:"Capabilities the role grants, for display"`
	CreatedAt string   `json:"created_at"`
}

// ListNamespaceMembersInput is the request for GET /api/v1/namespaces/{id}/members.
type ListNamespaceMembersInput struct {
	ID string `path:"id" doc:"Namespace UUID" format:"uuid"`
}

// ListNamespaceMembersOutput is the response for GET /api/v1/namespaces/{id}/members.
type ListNamespaceMembersOutput struct {
	Body struct {
		Data []NamespaceMemberResponse `json:"data"`
	}
}

// SetNamespaceMemberInput is the request for
// PUT /api/v1/namespaces/{id}/members/{user_id}. It is a PUT rather than a
// POST/PATCH pair because the caller states the membership they want: adding a
// member and changing one's role are the same statement.
type SetNamespaceMemberInput struct {
	ID     string `path:"id" doc:"Namespace UUID" format:"uuid"`
	UserID string `path:"user_id" doc:"UUID of the user to grant a role to" format:"uuid"`
	Body   struct {
		Role string `json:"role" enum:"owner,maintainer,security,developer,viewer" doc:"Role to grant in this namespace"`
	}
}

// SetNamespaceMemberOutput is the response for
// PUT /api/v1/namespaces/{id}/members/{user_id}.
type SetNamespaceMemberOutput struct {
	Body NamespaceMemberResponse
}

// RemoveNamespaceMemberInput is the request for
// DELETE /api/v1/namespaces/{id}/members/{user_id}.
type RemoveNamespaceMemberInput struct {
	ID     string `path:"id" doc:"Namespace UUID" format:"uuid"`
	UserID string `path:"user_id" doc:"UUID of the member to remove" format:"uuid"`
}
