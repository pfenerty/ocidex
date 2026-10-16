package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/version"
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

func TestAPIVersion_ReportsBuild(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/", nil)
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusOK)
	var body struct {
		Version string `json:"version"`
		Build   string `json:"build"`
	}
	is.NoErr(json.NewDecoder(w.Body).Decode(&body))
	is.Equal(body.Version, "v1")
	wantBuild, _, _ := version.Info()
	is.Equal(body.Build, wantBuild)
}

func TestOpenAPIInfoVersion_IsContractVersion(t *testing.T) {
	is := is.New(t)
	h := newTestHandlerWithPinger(&fakeSBOMService{}, &fakeSearchService{}, &fakePinger{})
	_ = newTestRouterFromHandler(h)

	is.Equal(h.API().OpenAPI().Info.Version, api.ContractVersion)
}
