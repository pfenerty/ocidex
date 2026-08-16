package api

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// SourceResponse is a source as returned by the API. A source is the ingest
// channel an SBOM arrived through (ADR-039); an 'oci_registry' source has a
// matching registry row carrying its pull config and trust policy.
type SourceResponse struct {
	ID            string `json:"id"`
	NamespaceID   string `json:"namespace_id"`
	NamespaceName string `json:"namespace_name,omitempty" doc:"Owning namespace name; populated on list responses"`
	Kind          string `json:"kind" enum:"oci_registry,upload" doc:"Ingest channel kind"`
	Name          string `json:"name"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// ListSourcesInput is the request for GET /api/v1/sources.
type ListSourcesInput struct {
	NamespaceID string `query:"namespace_id" doc:"Limit to sources in this namespace"`
}

// ListSourcesOutput is the response for GET /api/v1/sources.
type ListSourcesOutput struct {
	Body struct {
		Data []SourceResponse `json:"data"`
	}
}

// GetSourceInput is the request for GET /api/v1/sources/{id}.
type GetSourceInput struct {
	ID string `path:"id" doc:"Source UUID" format:"uuid"`
}

// GetSourceOutput is the response for GET /api/v1/sources/{id}.
type GetSourceOutput struct {
	Body SourceResponse
}

// CreateSourceInput is the request for POST /api/v1/sources. Only upload
// sources are created here; an OCI registry source is created together with
// its registry row via POST /api/v1/registries.
type CreateSourceInput struct {
	Body struct {
		NamespaceID string `json:"namespace_id" format:"uuid" doc:"Owning namespace UUID"`
		Name        string `json:"name" minLength:"1" maxLength:"100" doc:"Source name, unique within the namespace"`
	}
}

// CreateSourceOutput is the response for POST /api/v1/sources.
type CreateSourceOutput struct {
	Body SourceResponse
}

// UpdateSourceInput is the request for PATCH /api/v1/sources/{id}. Kind is
// immutable: changing it would strand or orphan the registry subtype row.
type UpdateSourceInput struct {
	ID   string `path:"id" doc:"Source UUID" format:"uuid"`
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"100" doc:"New source name"`
	}
}

// UpdateSourceOutput is the response for PATCH /api/v1/sources/{id}.
type UpdateSourceOutput struct {
	Body SourceResponse
}

// DeleteSourceInput is the request for DELETE /api/v1/sources/{id}.
type DeleteSourceInput struct {
	ID string `path:"id" doc:"Source UUID" format:"uuid"`
}
