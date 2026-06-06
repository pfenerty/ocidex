package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestListArtifacts(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"art-1","name":"myapp","type":"container","sbomCount":3,"sufficientSbomCount":2}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListArtifacts(context.Background(), PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Id, "art-1")
}

func TestGetArtifact(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/art-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"art-1","name":"myapp","type":"container","sbomCount":3,"sufficientSbomCount":2,"versionCount":5,"createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	art, err := newTestClient(srv).GetArtifact(context.Background(), "art-1")
	is.NoErr(err)
	is.Equal(art.Id, "art-1")
	is.Equal(art.Name, "myapp")
}

func TestGetArtifactChangelog(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/art-1/changelog")
		is.Equal(r.URL.Query().Get("arch"), "amd64")
		is.Equal(r.URL.Query().Get("flavor"), "standard")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"artifactId":"art-1"}`))
	}))
	defer srv.Close()

	arch := "amd64"
	flavor := "standard"
	params := GetArtifactChangelogParams{Arch: &arch, Flavor: &flavor}
	changelog, err := newTestClient(srv).GetArtifactChangelog(context.Background(), "art-1", params)
	is.NoErr(err)
	is.Equal(changelog.ArtifactId, "art-1")
}

func TestGetArtifactLicenseSummary(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/art-1/license-summary")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"licenses":[{"id":"lic-1","name":"MIT","category":"permissive","componentCount":10}]}`))
	}))
	defer srv.Close()

	summary, err := newTestClient(srv).GetArtifactLicenseSummary(context.Background(), "art-1")
	is.NoErr(err)
	is.True(summary.Licenses != nil)
	is.Equal(len(*summary.Licenses), 1)
}

func TestListArtifactSBOMs(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/art-1/sboms")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"sbom-1","specVersion":"1.4","sufficient":true,"version":1,"createdAt":"2024-01-01T00:00:00Z"}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListArtifactSBOMs(context.Background(), "art-1", PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Id, "sbom-1")
}

func TestListArtifactVersions(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/art-1/versions")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"versionKey":"v1.0","sbomId":"sbom-1","sbomCount":1,"architectures":["amd64"],"createdAt":"2024-01-01T00:00:00Z","sufficient":true}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListArtifactVersions(context.Background(), "art-1", PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].VersionKey, "v1.0")
}

func TestGetArtifact_NotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetArtifact(context.Background(), "missing")
	is.True(errors.Is(err, ErrNotFound))
}
