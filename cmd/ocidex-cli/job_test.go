package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testJobID = "66666666-6666-6666-6666-666666666666"

func testScanJob() client.ScanJobResponse {
	return client.ScanJobResponse{
		Id: testJobID, State: "failed", Repository: "pfenerty/ocidex",
		Tag: ptr("v1.0.0"), Digest: "sha256:abc", Attempts: 3,
		CreatedAt: "2026-08-01T09:00:00Z",
		LastError: ptr("manifest unknown"),
	}
}

func TestJobList(t *testing.T) {
	is := is.New(t)
	var got client.JobFilter
	fake := &client.FakeClient{
		ListJobsFn: func(_ context.Context, filter client.JobFilter, opts client.PageOpts) (client.Page[client.ScanJobResponse], error) {
			got = filter
			is.Equal(opts.Offset, int32(10))
			return client.Page[client.ScanJobResponse]{
				Data:       []client.ScanJobResponse{testScanJob()},
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "job", "list", "--state", "failed", "--offset", "10")
	is.NoErr(err)
	is.Equal(got.State, "failed")

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[1], "pfenerty/ocidex"))
	is.True(strings.Contains(lines[1], "v1.0.0"))
}

// The plural is what people type; the singular is what the docs say.
func TestJobsAlias(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		ListJobsFn: func(context.Context, client.JobFilter, client.PageOpts) (client.Page[client.ScanJobResponse], error) {
			called = true
			return client.Page[client.ScanJobResponse]{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "jobs", "list")
	is.NoErr(err)
	is.True(called)
}

// An unrecognised state is rejected here rather than sent: the server ignores
// one it does not know, so the user would silently get an unfiltered listing.
func TestJobListRejectsUnknownState(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		ListJobsFn: func(context.Context, client.JobFilter, client.PageOpts) (client.Page[client.ScanJobResponse], error) {
			called = true
			return client.Page[client.ScanJobResponse]{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "job", "list", "--state", "borked")
	is.True(err != nil)
	is.True(!called)
	is.True(strings.Contains(err.Error(), "queued"))
}

func TestJobGet(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetJobFn: func(_ context.Context, id string) (client.ScanJobResponse, error) {
			is.Equal(id, testJobID)
			return testScanJob(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "job", "get", testJobID)
	is.NoErr(err)
	// Attempts and the error are the two fields that say whether a failure is
	// stuck or merely slow, so detail must carry them.
	is.True(strings.Contains(stdout, "manifest unknown"))
	is.True(strings.Contains(stdout, "sha256:abc"))
}

func TestJobGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetJobFn: func(_ context.Context, id string) (client.ScanJobResponse, error) {
			return testScanJob(), nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "job", "get", testJobID, "-o", "json")
	is.NoErr(err)
	is.Equal(stderr, "")

	var got client.ScanJobResponse
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.Attempts, int32(3))
}

func TestJobRetry(t *testing.T) {
	is := is.New(t)
	var gotID string
	fake := &client.FakeClient{
		RetryJobFn: func(_ context.Context, id string) error {
			gotID = id
			return nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "job", "retry", testJobID)
	is.NoErr(err)
	is.Equal(gotID, testJobID)
	// Confirmation is guidance, not data: stderr, so stdout stays empty for a
	// caller that is only checking the exit code.
	is.Equal(stdout, "")
	is.True(strings.Contains(stderr, "requeued"))
}

func TestJobRetryError(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		RetryJobFn: func(context.Context, string) error {
			return errors.New("forbidden")
		},
	}

	_, _, err := runCLI(t, fake, "job", "retry", testJobID)
	is.True(err != nil)
}
