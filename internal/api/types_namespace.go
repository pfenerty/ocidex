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
