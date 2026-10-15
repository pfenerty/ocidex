package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
)

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		path        string
		wantNoStore bool
	}{
		{"/api/v1/auth/keys", true},
		{"/api/v1/auth/identities", true},
		{"/api/v1/users/me", true},
		{"/api/v1/users/me/namespaces", true},
		{"/auth/callback", true},
		{"/api/v1/artifacts", false},
		{"/api/v1/users/someone", false},
		{"/health", false},
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			is := is.New(t)
			w := httptest.NewRecorder()
			api.SecurityHeaders(ok).ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))
			is.Equal(w.Header().Get("X-Content-Type-Options"), "nosniff")
			is.Equal(w.Header().Get("Cache-Control") == "no-store", tt.wantNoStore)
		})
	}
}
