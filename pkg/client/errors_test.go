package client

import (
	"errors"
	"testing"

	"github.com/matryer/is"
)

func TestMapError(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       []byte
		wantSentinel error
		wantAPIErr   *APIError
	}{
		{
			name:         "404 returns ErrNotFound",
			status:       404,
			body:         []byte(`{"status":404,"detail":"not found"}`),
			wantSentinel: ErrNotFound,
		},
		{
			name:         "403 returns ErrForbidden",
			status:       403,
			body:         []byte(`{"status":403,"detail":"forbidden"}`),
			wantSentinel: ErrForbidden,
		},
		{
			name:         "409 returns ErrConflict",
			status:       409,
			body:         []byte(`{"status":409,"detail":"conflict"}`),
			wantSentinel: ErrConflict,
		},
		{
			name:         "500 returns APIError with decoded detail",
			status:       500,
			body:         []byte(`{"status":500,"detail":"internal error"}`),
			wantAPIErr:   &APIError{Status: 500, Detail: "internal error"},
		},
		{
			name:         "422 returns APIError with raw body fallback on malformed JSON",
			status:       422,
			body:         []byte(`bad json`),
			wantAPIErr:   &APIError{Status: 422, Detail: "bad json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			err := mapError(tt.status, tt.body)
			is.True(err != nil)

			if tt.wantSentinel != nil {
				is.True(errors.Is(err, tt.wantSentinel))
				return
			}
			var apiErr *APIError
			is.True(errors.As(err, &apiErr))
			is.Equal(apiErr.Status, tt.wantAPIErr.Status)
			is.Equal(apiErr.Detail, tt.wantAPIErr.Detail)
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	is := is.New(t)
	e := &APIError{Status: 503, Detail: "service unavailable"}
	is.Equal(e.Error(), "HTTP 503: service unavailable")
}
