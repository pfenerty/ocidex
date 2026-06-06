package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestSearchComponents(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/components")
		is.Equal(r.URL.Query().Get("name"), "openssl")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"comp-1","name":"openssl","type":"library","sbomCount":5,"sufficientSbomCount":4}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).SearchComponents(context.Background(), "openssl", PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Name, "openssl")
}

func TestSearchDistinctComponents_WithQuery(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/components/distinct")
		is.Equal(r.URL.Query().Get("name"), "curl")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"name":"curl","type":"library","sbomCount":3,"versionCount":2}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).SearchDistinctComponents(context.Background(), "curl", PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Name, "curl")
}

func TestSearchDistinctComponents_EmptyQuery(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Query().Get("name"), "") // name must not be set
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[],"pagination":{"total":0,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).SearchDistinctComponents(context.Background(), "", PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 0)
}

func TestGetComponent(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/components/comp-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"comp-1","name":"openssl","type":"library","sbomId":"sbom-1","isDirect":true}`))
	}))
	defer srv.Close()

	comp, err := newTestClient(srv).GetComponent(context.Background(), "comp-1")
	is.NoErr(err)
	is.Equal(comp.Id, "comp-1")
	is.Equal(comp.Name, "openssl")
}

func TestGetComponentVersions(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/components/versions")
		is.Equal(r.URL.Query().Get("name"), "openssl")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"versions":[{"name":"openssl","version":"3.0.1","type":"library","id":"comp-v1","sbomId":"sbom-1","isDirect":false}]}`))
	}))
	defer srv.Close()

	out, err := newTestClient(srv).GetComponentVersions(context.Background(), GetComponentVersionsParams{Name: "openssl"})
	is.NoErr(err)
	is.True(out.Versions != nil)
	is.Equal(len(*out.Versions), 1)
}

func TestListComponentPurlTypes(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/components/purl-types")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"types":["golang","npm","pypi"]}`))
	}))
	defer srv.Close()

	types, err := newTestClient(srv).ListComponentPurlTypes(context.Background())
	is.NoErr(err)
	is.Equal(len(types), 3)
	is.Equal(types[0], "golang")
}

func TestListSBOMComponents(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/sbom-1/components")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"components":[{"id":"comp-1","name":"openssl","type":"library","sbomCount":1,"sufficientSbomCount":1}]}`))
	}))
	defer srv.Close()

	comps, err := newTestClient(srv).ListSBOMComponents(context.Background(), "sbom-1")
	is.NoErr(err)
	is.Equal(len(comps), 1)
	is.Equal(comps[0].Name, "openssl")
}

func TestGetSBOMDependencies(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/sbom-1/dependencies")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"edges":[{"from":"comp-1","to":"comp-2"}]}`))
	}))
	defer srv.Close()

	graph, err := newTestClient(srv).GetSBOMDependencies(context.Background(), "sbom-1")
	is.NoErr(err)
	is.True(graph.Edges != nil)
	is.Equal(len(*graph.Edges), 1)
}

func TestGetComponent_NotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetComponent(context.Background(), "missing")
	is.True(errors.Is(err, ErrNotFound))
}
