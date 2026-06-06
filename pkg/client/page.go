package client

// Page is a paginated result from a list endpoint.
// PaginationMeta is the generated type from types.go.
type Page[T any] struct {
	Data       []T
	Pagination PaginationMeta
}

// HasMore reports whether there are more results after this page.
func (p Page[T]) HasMore() bool {
	return int64(p.Pagination.Offset)+int64(p.Pagination.Limit) < p.Pagination.Total
}

// NextOffset returns the offset to pass for the next page.
func (p Page[T]) NextOffset() int32 {
	return p.Pagination.Offset + p.Pagination.Limit
}

// PageOpts controls pagination for list endpoints.
// Zero values use server defaults (limit=50, offset=0).
type PageOpts struct {
	Limit  int32
	Offset int32
}
