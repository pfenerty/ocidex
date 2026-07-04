package vuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestModifiedCSVFetcherParsesMaxTime(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = fmt.Fprint(w, "id,modified\n")
		_, _ = fmt.Fprint(w, "CVE-2024-0001,2024-01-15T10:00:00Z\n")
		_, _ = fmt.Fprint(w, "CVE-2024-0002,2024-03-20T08:30:00Z\n") // latest
		_, _ = fmt.Fprint(w, "CVE-2024-0003,2024-02-10T12:00:00Z\n")
	}))
	defer srv.Close()

	fetcher := NewModifiedCSVFetcher(srv.URL, srv.Client())
	got, err := fetcher.FetchMaxModifiedAt(context.Background(), "npm")
	is.NoErr(err)

	want, _ := time.Parse(time.RFC3339, "2024-03-20T08:30:00Z")
	is.Equal(got, want)
}

func TestModifiedCSVFetcherNoHeaderRow(t *testing.T) {
	is := is.New(t)

	// CSV without a header — all rows should be parsed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "CVE-2024-0001,2024-05-01T00:00:00Z\n")
		_, _ = fmt.Fprint(w, "CVE-2024-0002,2024-06-01T00:00:00Z\n")
	}))
	defer srv.Close()

	fetcher := NewModifiedCSVFetcher(srv.URL, srv.Client())
	got, err := fetcher.FetchMaxModifiedAt(context.Background(), "PyPI")
	is.NoErr(err)

	want, _ := time.Parse(time.RFC3339, "2024-06-01T00:00:00Z")
	is.Equal(got, want)
}

func TestModifiedCSVFetcherEmptyBodyReturnsZero(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := NewModifiedCSVFetcher(srv.URL, srv.Client())
	got, err := fetcher.FetchMaxModifiedAt(context.Background(), "Go")
	is.NoErr(err)
	is.True(got.IsZero())
}

func TestModifiedCSVFetcherHTTPErrorReturnsError(t *testing.T) {
	is := is.New(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	fetcher := NewModifiedCSVFetcher(srv.URL, srv.Client())
	_, err := fetcher.FetchMaxModifiedAt(context.Background(), "npm")
	is.True(err != nil)
}

func TestModifiedCSVFetcherURLContainsEcosystem(t *testing.T) {
	is := is.New(t)

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fetcher := NewModifiedCSVFetcher(srv.URL, srv.Client())
	_, _ = fetcher.FetchMaxModifiedAt(context.Background(), "Maven")
	is.Equal(gotPath, "/Maven/modified_id.csv")
}
