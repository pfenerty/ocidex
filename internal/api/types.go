// Package api's request and response types are split by domain, one file per
// handler file: types_sbom.go beside sbom.go, types_registry.go beside
// registry.go, and so on. What stays here is what every domain shares.
package api

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// PaginationParams is embedded in input structs for paginated endpoints.
type PaginationParams struct {
	Limit  int32 `query:"limit" default:"20" minimum:"1" maximum:"200" doc:"Maximum number of results per page"`
	Offset int32 `query:"offset" default:"0" minimum:"0" doc:"Number of results to skip"`
}

// PaginationMeta contains pagination metadata in response bodies.
type PaginationMeta struct {
	Total  int64 `json:"total" doc:"Total number of matching results"`
	Limit  int32 `json:"limit" doc:"The limit that was applied"`
	Offset int32 `json:"offset" doc:"The offset that was applied"`
}

// CursorParams is embedded in input structs for keyset-paginated endpoints.
// Keyset paging replaces OFFSET (which scans-and-discards on deep pages) and
// drops the per-page COUNT(*) total; the client pages forward with an opaque
// cursor and stops when hasMore is false.
type CursorParams struct {
	Limit  int32  `query:"limit" default:"20" minimum:"1" maximum:"200" doc:"Maximum number of results per page"`
	Cursor string `query:"cursor" doc:"Opaque cursor from a previous response's nextCursor; omit for the first page"`
}

// CursorMeta contains keyset-pagination metadata in response bodies.
type CursorMeta struct {
	Limit      int32   `json:"limit" doc:"The limit that was applied"`
	HasMore    bool    `json:"hasMore" doc:"Whether more results exist after this page"`
	NextCursor *string `json:"nextCursor,omitempty" doc:"Opaque cursor to fetch the next page; null when hasMore is false"`
}
