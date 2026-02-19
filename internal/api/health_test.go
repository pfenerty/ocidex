package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

type fakePinger struct {
	err error
}

func (f *fakePinger) Ping(_ context.Context) error {
	return f.err
}

func TestHealthCheck(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
	is.True(w.Body.String() != "")
}

func TestReadinessCheck_Healthy(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ready", nil)

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
}

func TestReadinessCheck_Unavailable(t *testing.T) {
	is := is.New(t)

	// Build a router with a failing pinger.
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{err: errors.New("connection refused")})
	router := newTestRouterFromHandler(h)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ready", nil)

	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusServiceUnavailable)
}
