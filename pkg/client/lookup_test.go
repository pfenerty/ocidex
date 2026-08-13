package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func strptr(s string) *string { return &s }

func TestLookupArtifact(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/artifacts/lookup")
		is.Equal(r.URL.Query().Get("name"), "myapp")
		is.Equal(r.URL.Query().Get("type"), "container")
		// An empty qualifier is omitted rather than sent as an empty value.
		_, hasGroup := r.URL.Query()["group"]
		is.True(!hasGroup)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"art-1","name":"myapp","type":"container","sbomCount":3,"sufficientSbomCount":2,"versionCount":5,"createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	art, err := newTestClient(srv).LookupArtifact(context.Background(), LookupArtifactParams{
		Name:  "myapp",
		Type:  strptr("container"),
		Group: strptr(""),
	})
	is.NoErr(err)
	is.Equal(art.Id, "art-1")
}

func TestLookupArtifactConflictSurfacesCandidates(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"status":409,"title":"Ambiguous lookup","detail":"2 visible artifact candidates match","candidates":[{"id":"art-1","qualifiers":{"type":"container"}},{"id":"art-2","qualifiers":{"type":"application"}}]}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).LookupArtifact(context.Background(), LookupArtifactParams{Name: "myapp"})
	is.True(err != nil)
	// Callers that only test the sentinel keep working.
	is.True(errors.Is(err, ErrConflict))

	var conflict *ConflictError
	is.True(errors.As(err, &conflict))
	is.Equal(len(conflict.Candidates), 2)
	is.Equal(conflict.Candidates[0].Id, "art-1")
	is.Equal(conflict.Candidates[0].Qualifiers["type"], "container")
	is.Equal(conflict.Candidates[1].Id, "art-2")
	is.Equal(conflict.Detail, "2 visible artifact candidates match")
}

func TestLookupArtifactNotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"artifact not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).LookupArtifact(context.Background(), LookupArtifactParams{Name: "nope"})
	is.True(errors.Is(err, ErrNotFound))
}

func TestLookupSBOM(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/sboms/lookup")
		q := r.URL.Query()
		is.Equal(q.Get("artifact"), "myapp")
		is.Equal(q.Get("version"), "1.2.3")
		is.Equal(q.Get("arch"), "amd64")
		is.Equal(q.Get("include"), "raw")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sbom-1","digest":"sha256:abc","format":"CycloneDX","specVersion":"1.5","createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	sbom, err := newTestClient(srv).LookupSBOM(context.Background(), LookupSbomParams{
		Artifact: strptr("myapp"),
		Version:  strptr("1.2.3"),
		Arch:     strptr("amd64"),
		Include:  strptr("raw"),
	})
	is.NoErr(err)
	is.Equal(sbom.Id, "sbom-1")
}

func TestLookupSBOMByDigest(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		is.Equal(q.Get("digest"), "sha256:abc")
		_, hasArtifact := q["artifact"]
		is.True(!hasArtifact)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sbom-1","digest":"sha256:abc","format":"CycloneDX","specVersion":"1.5","createdAt":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	sbom, err := newTestClient(srv).LookupSBOM(context.Background(), LookupSbomParams{Digest: strptr("sha256:abc")})
	is.NoErr(err)
	is.Equal(sbom.Id, "sbom-1")
}

func TestLookupLicense(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/licenses/lookup")
		is.Equal(r.URL.Query().Get("spdxId"), "Apache-2.0")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"lic-1","name":"Apache License 2.0","spdxId":"Apache-2.0","category":"permissive","componentCount":42}`))
	}))
	defer srv.Close()

	license, err := newTestClient(srv).LookupLicense(context.Background(), "Apache-2.0")
	is.NoErr(err)
	is.Equal(license.Id, "lic-1")
	is.Equal(license.ComponentCount, int64(42))
}

// A 409 without candidates — a duplicate registry name, say — must stay the
// bare sentinel rather than becoming an empty ConflictError.
func TestConflictWithoutCandidatesStaysSentinel(t *testing.T) {
	is := is.New(t)
	err := mapError(409, []byte(`{"status":409,"detail":"registry name already exists"}`))
	is.Equal(err, ErrConflict)

	var conflict *ConflictError
	is.True(!errors.As(err, &conflict))
}
