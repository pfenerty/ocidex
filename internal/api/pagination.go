package api

import (
	"github.com/pfenerty/ocidex/internal/service"
)

// paginationMeta builds offset-pagination metadata from a paged service result.
func paginationMeta[T any](r service.PagedResult[T]) PaginationMeta {
	return PaginationMeta{Total: r.Total, Limit: r.Limit, Offset: r.Offset}
}

// cursorMeta builds keyset-pagination metadata, deriving nextCursor from the
// last item via cursorFn when further results exist.
func cursorMeta[T any](data []T, hasMore bool, limit int32, cursorFn func(T) string) CursorMeta {
	meta := CursorMeta{Limit: limit, HasMore: hasMore}
	if hasMore && len(data) > 0 {
		next := cursorFn(data[len(data)-1])
		meta.NextCursor = &next
	}
	return meta
}
