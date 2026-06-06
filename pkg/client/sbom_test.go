package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestIngestSBOM(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodPost)
		is.Equal(r.URL.Path, "/api/v1/sboms")
		is.Equal(r.Header.Get("Content-Type"), "application/octet-stream")
		is.Equal(r.URL.Query().Get("version"), "1.0.0")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"sbom-1","status":"accepted","specVersion":"1.4","componentCount":42}`))
	}))
	defer srv.Close()

	ver := "1.0.0"
	params := IngestSbomParams{Version: &ver}
	resp, err := newTestClient(srv).IngestSBOM(context.Background(), []byte(`{}`), params)
	is.NoErr(err)
	is.Equal(resp.Id, "sbom-1")
	is.Equal(resp.Status, "accepted")
}

func TestGetSBOM(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/sbom-1")
		is.Equal(r.URL.Query().Get("include"), "raw")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sbom-1","specVersion":"1.4","sufficient":true,"version":1,"createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	sbom, err := newTestClient(srv).GetSBOM(context.Background(), "sbom-1", true)
	is.NoErr(err)
	is.Equal(sbom.Id, "sbom-1")
	is.True(sbom.Sufficient)
}

func TestGetSBOM_NoRaw(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Query().Get("include"), "")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sbom-1","specVersion":"1.4","sufficient":false,"version":1,"createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetSBOM(context.Background(), "sbom-1", false)
	is.NoErr(err)
}

func TestListSBOMs(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"sbom-1","specVersion":"1.4","sufficient":true,"version":1,"createdAt":"2024-01-01T00:00:00Z"}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListSBOMs(context.Background(), PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Id, "sbom-1")
	is.Equal(page.Pagination.Total, int64(1))
}

func TestDeleteSBOM(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.Method, http.MethodDelete)
		is.Equal(r.URL.Path, "/api/v1/sboms/sbom-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteSBOM(context.Background(), "sbom-1")
	is.NoErr(err)
}

func TestDiffSBOMs(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/diff")
		is.Equal(r.URL.Query().Get("from"), "sbom-1")
		is.Equal(r.URL.Query().Get("to"), "sbom-2")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"from":{"id":"sbom-1","createdAt":"2024-01-01T00:00:00Z"},"to":{"id":"sbom-2","createdAt":"2024-01-02T00:00:00Z"},"summary":{"added":5,"removed":2,"upgraded":0,"downgraded":0,"modified":1}}`))
	}))
	defer srv.Close()

	entry, err := newTestClient(srv).DiffSBOMs(context.Background(), "sbom-1", "sbom-2")
	is.NoErr(err)
	is.Equal(entry.From.Id, "sbom-1")
	is.Equal(entry.To.Id, "sbom-2")
	is.Equal(entry.Summary.Added, int64(5))
}

func TestGetDiffTree(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/diff-tree")
		is.Equal(r.URL.Query().Get("from"), "sbom-1")
		is.Equal(r.URL.Query().Get("to"), "sbom-2")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"from":{"id":"sbom-1","createdAt":"2024-01-01T00:00:00Z"},"to":{"id":"sbom-2","createdAt":"2024-01-02T00:00:00Z"},"summary":{"added":3,"removed":0,"upgraded":1,"downgraded":0,"modified":0}}`))
	}))
	defer srv.Close()

	tree, err := newTestClient(srv).GetDiffTree(context.Background(), "sbom-1", "sbom-2")
	is.NoErr(err)
	is.Equal(tree.From.Id, "sbom-1")
	is.Equal(tree.Summary.Added, int64(3))
}

func TestGetSBOM_NotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetSBOM(context.Background(), "missing", false)
	is.True(errors.Is(err, ErrNotFound))
}
