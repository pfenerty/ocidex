package client

import (
	"testing"

	"github.com/matryer/is"
)

func TestPage_HasMore(t *testing.T) {
	tests := []struct {
		name  string
		page  Page[string]
		want  bool
	}{
		{
			name: "more results exist",
			page: Page[string]{Pagination: PaginationMeta{Total: 100, Limit: 50, Offset: 0}},
			want: true,
		},
		{
			name: "on last page exactly",
			page: Page[string]{Pagination: PaginationMeta{Total: 50, Limit: 50, Offset: 0}},
			want: false,
		},
		{
			name: "offset past end",
			page: Page[string]{Pagination: PaginationMeta{Total: 10, Limit: 50, Offset: 10}},
			want: false,
		},
		{
			name: "mid-pagination",
			page: Page[string]{Pagination: PaginationMeta{Total: 200, Limit: 50, Offset: 50}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(tt.page.HasMore(), tt.want)
		})
	}
}

func TestPage_NextOffset(t *testing.T) {
	is := is.New(t)
	p := Page[string]{Pagination: PaginationMeta{Limit: 25, Offset: 50}}
	is.Equal(p.NextOffset(), int32(75))
}
