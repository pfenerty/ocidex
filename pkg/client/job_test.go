package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestListJobs(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/jobs")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"job-1","state":"succeeded","repository":"myrepo","digest":"sha256:abc","attempts":1,"created_at":"2024-01-01T00:00:00Z"}],"pagination":{"total":1,"limit":50,"offset":0}}`))
	}))
	defer srv.Close()

	page, err := newTestClient(srv).ListJobs(context.Background(), PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 1)
	is.Equal(page.Data[0].Id, "job-1")
	is.Equal(string(page.Data[0].State), "succeeded")
}

func TestGetJob(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/jobs/job-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"job-1","state":"running","repository":"myrepo","digest":"sha256:abc","attempts":1,"created_at":"2024-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	job, err := newTestClient(srv).GetJob(context.Background(), "job-1")
	is.NoErr(err)
	is.Equal(job.Id, "job-1")
	is.Equal(string(job.State), "running")
}

func TestGetDashboardStats(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		is.Equal(r.URL.Path, "/api/v1/stats")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"artifact_count":10,"sbom_count":25,"package_count":500,"license_count":12,"version_count":30}`))
	}))
	defer srv.Close()

	stats, err := newTestClient(srv).GetDashboardStats(context.Background())
	is.NoErr(err)
	is.Equal(stats.ArtifactCount, int64(10))
	is.Equal(stats.SbomCount, int64(25))
}

func TestGetJob_NotFound(t *testing.T) {
	is := is.New(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"detail":"not found"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).GetJob(context.Background(), "missing")
	is.True(errors.Is(err, ErrNotFound))
}
