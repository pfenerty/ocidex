package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

// lookupCountingAuthService counts credential lookups and records whether each
// ran under a deadline.
type lookupCountingAuthService struct {
	fakeAuthService
	mu          sync.Mutex
	lookups     int
	hadDeadline []bool
}

func (f *lookupCountingAuthService) note(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	_, ok := ctx.Deadline()
	f.hadDeadline = append(f.hadDeadline, ok)
}

func (f *lookupCountingAuthService) ValidateSession(ctx context.Context, token string) (service.AuthUser, error) {
	f.note(ctx)
	return f.fakeAuthService.ValidateSession(ctx, token)
}

func (f *lookupCountingAuthService) ValidateAPIKey(ctx context.Context, token string) (service.AuthUser, error) {
	f.note(ctx)
	return f.fakeAuthService.ValidateAPIKey(ctx, token)
}

func orderRouter(authSvc service.AuthService) http.Handler {
	h := api.NewHandler(nil, nil, authSvc, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil, &config.Config{})
	return api.NewRouter(h, "https://ocidex.example", "", "https://api.ocidex.example")
}

// A write the cross-origin guard rejects costs no credential lookup: the guard
// runs before authentication (ocidex-89c9.4).
func TestCrossOriginRejectionSkipsCredentialLookup(t *testing.T) {
	is := is.New(t)
	authSvc := &lookupCountingAuthService{}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/jobs/retry-failed", nil)
	r.AddCookie(&http.Cookie{Name: "ocidex_session", Value: "sess"})
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()

	orderRouter(authSvc).ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusForbidden)
	is.Equal(authSvc.lookups, 0)
}

// Authentication runs inside the request timeout, so its lookups carry the
// request's deadline (ocidex-89c9.4).
func TestAuthenticationRunsUnderRequestTimeout(t *testing.T) {
	for _, tt := range []struct {
		name string
		set  func(*http.Request)
	}{
		{"api key", func(r *http.Request) { r.Header.Set("Authorization", "Bearer key") }},
		{"session cookie", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "ocidex_session", Value: "sess"}) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			authSvc := &lookupCountingAuthService{}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/artifacts", nil)
			tt.set(r)

			orderRouter(authSvc).ServeHTTP(httptest.NewRecorder(), r)

			is.Equal(authSvc.lookups, 1)
			is.True(authSvc.hadDeadline[0])
		})
	}
}
