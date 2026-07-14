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

// CursorPage is a paginated result from a cursor-based list endpoint.
// CursorMeta is the generated type from types.go.
type CursorPage[T any] struct {
	Data       []T
	Pagination CursorMeta
}

// PageOpts controls pagination for list endpoints.
// Zero values use server defaults (limit=50, offset=0).
type PageOpts struct {
	Limit  int32
	Offset int32
}

// derefSlice returns the dereferenced slice, or nil if the pointer is nil.
// Used to unwrap the *[]T fields that generated list response bodies carry.
func derefSlice[T any](p *[]T) []T {
	if p == nil {
		return nil
	}
	return *p
}
