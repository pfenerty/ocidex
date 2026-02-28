package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

// catalogTestServer builds a fake registry that serves a manifest and config blob.
// manifestAnnotations and configLabels control what the fake registry returns.
func catalogTestServer(t *testing.T, manifestAnnotations, configLabels map[string]string) *httptest.Server {
	t.Helper()

	configBlob := map[string]any{
		"architecture": "amd64",
		"created":      "2024-01-01T00:00:00Z",
		"config": map[string]any{
			"Labels": configLabels,
		},
	}
	configBytes, _ := json.Marshal(configBlob)

	manifest := map[string]any{
		"config": map[string]any{
			"digest": "sha256:configdigest",
		},
		"annotations": manifestAnnotations,
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/repo/manifests/sha256:testdigest":
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.URL.Path == "/v2/repo/blobs/sha256:configdigest":
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(configBytes)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestOciGetImageMetadata(t *testing.T) {
	is := is.New(t)

	t.Run("version from manifest annotation wins over label", func(t *testing.T) {
		is := is.New(t)
		srv := catalogTestServer(t,
			map[string]string{"org.opencontainers.image.version": "1.2.3"},
			map[string]string{"org.opencontainers.image.version": "from-label"},
		)
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta.imageVersion, "1.2.3")
	})

	t.Run("label version used when no annotation", func(t *testing.T) {
		is := is.New(t)
		srv := catalogTestServer(t,
			nil,
			map[string]string{"org.opencontainers.image.version": "2.0.0"},
		)
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta.imageVersion, "2.0.0")
	})

	t.Run("label-schema version fallback", func(t *testing.T) {
		is := is.New(t)
		srv := catalogTestServer(t,
			nil,
			map[string]string{"org.label-schema.version": "3.0"},
		)
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta.imageVersion, "3.0")
	})

	t.Run("config.Created wins over manifest annotation for buildDate", func(t *testing.T) {
		is := is.New(t)
		// annotation says one date, config blob says another — config wins
		srv := catalogTestServer(t,
			map[string]string{"org.opencontainers.image.created": "2025-06-01T00:00:00Z"},
			nil,
		)
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		// config blob created is "2024-01-01T00:00:00Z" — that takes priority
		is.Equal(meta.buildDate, "2024-01-01T00:00:00Z")
	})

	t.Run("manifest annotation used when config.Created is empty", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v2/repo/manifests/sha256:testdigest":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"config":      map[string]any{"digest": "sha256:configdigest"},
					"annotations": map[string]string{"org.opencontainers.image.created": "2025-06-01T00:00:00Z"},
				})
			case r.URL.Path == "/v2/repo/blobs/sha256:configdigest":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"architecture": "amd64",
					// no "created" field
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta.buildDate, "2025-06-01T00:00:00Z")
	})

	t.Run("label fallback for buildDate", func(t *testing.T) {
		is := is.New(t)
		// Serve a config blob with no top-level created but a label
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v2/repo/manifests/sha256:testdigest":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"config":      map[string]any{"digest": "sha256:configdigest"},
					"annotations": map[string]string{},
				})
			case r.URL.Path == "/v2/repo/blobs/sha256:configdigest":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"architecture": "amd64",
					"config": map[string]any{
						"Labels": map[string]string{
							"org.label-schema.build-date": "2023-05-10",
						},
					},
				})
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta.buildDate, "2023-05-10")
	})

	t.Run("HTTP error returns zero value", func(t *testing.T) {
		is := is.New(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "server error", http.StatusInternalServerError)
		}))
		defer srv.Close()
		meta := ociGetImageMetadata(t.Context(), srv.Client(), srv.URL, "repo", "sha256:testdigest")
		is.Equal(meta, imageMetadata{})
	})
}
