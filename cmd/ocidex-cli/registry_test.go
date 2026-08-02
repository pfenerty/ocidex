package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testRegistryID = "22222222-2222-2222-2222-222222222222"

func testRegistry() client.RegistryResponse {
	last := "2026-08-01T09:00:00Z"
	repos := []string{"ocidex", "apko-cicd"}
	return client.RegistryResponse{
		Id:                  testRegistryID,
		Name:                "ghcr",
		Url:                 "ghcr.io",
		Type:                "ghcr",
		ScanMode:            "poll",
		Visibility:          "private",
		Enabled:             true,
		Insecure:            false,
		IncludeUntagged:     true,
		PollIntervalMinutes: 60,
		Repositories:        &repos,
		LastPolledAt:        &last,
		VerificationMode:    "keyless",
		CreatedAt:           "2026-07-01T09:00:00Z",
		UpdatedAt:           "2026-07-02T09:00:00Z",
	}
}

// runCLI executes the CLI against fake, returning stdout and stderr separately
// so a test can tell rendered output from progress and prompts.
func runCLI(t *testing.T, fake *client.FakeClient, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	// An empty config dir: the developer's own config must not reach the test.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OCIDEX_API_KEY", "ocidex_test")

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	cmd, cfg := newRootCmd()
	cfg.newClient = func(client.Config) client.Client { return fake }
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestRegistryList(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListRegistriesFn: func(_ context.Context, opts client.PageOpts) (client.Page[client.RegistryResponse], error) {
			is.Equal(opts.Limit, int32(5))
			is.Equal(opts.Offset, int32(10))
			return client.Page[client.RegistryResponse]{
				Data:       []client.RegistryResponse{testRegistry()},
				Pagination: client.PaginationMeta{Total: 1},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "registry", "list", "--limit", "5", "--offset", "10")
	is.NoErr(err)
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2) // header + one registry
	is.True(strings.Contains(lines[0], "SCAN MODE"))
	is.True(strings.Contains(lines[1], "ghcr.io"))
	is.True(strings.Contains(lines[1], "2026-08-01T09:00:00Z"))
}

// The count is a human aid, so it must not contaminate a piped table.
func TestRegistryListCountGoesToStderr(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListRegistriesFn: func(context.Context, client.PageOpts) (client.Page[client.RegistryResponse], error) {
			return client.Page[client.RegistryResponse]{
				Data:       []client.RegistryResponse{testRegistry()},
				Pagination: client.PaginationMeta{Total: 12},
			}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "registry", "list")
	is.NoErr(err)
	is.True(strings.Contains(stderr, "1 of 12"))
	is.True(!strings.Contains(stdout, "1 of 12"))
}

func TestRegistryGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetRegistryFn: func(_ context.Context, id string) (client.RegistryResponse, error) {
			is.Equal(id, testRegistryID)
			return testRegistry(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "registry", "get", testRegistryID, "-o", "json")
	is.NoErr(err)

	var got client.RegistryResponse
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.Url, "ghcr.io")
}

// A non-UUID reference is resolved by name rather than sent as an id.
func TestRegistryGetByName(t *testing.T) {
	is := is.New(t)
	called := ""
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) {
			t.Fatal("a name must not be sent to the by-id endpoint")
			return client.RegistryResponse{}, nil
		},
		GetRegistryByNameFn: func(_ context.Context, name string) (client.RegistryResponse, error) {
			called = name
			return testRegistry(), nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "get", "ghcr")
	is.NoErr(err)
	is.Equal(called, "ghcr")
}

func TestRegistryCreate(t *testing.T) {
	is := is.New(t)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("ghp_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var got client.CreateRegistryInputBody
	fake := &client.FakeClient{
		CreateRegistryFn: func(_ context.Context, body client.CreateRegistryInputBody) (client.CreateRegistryResponseBody, error) {
			got = body
			return client.CreateRegistryResponseBody{Id: testRegistryID, Name: body.Name}, nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "create",
		"--name", "ghcr", "--url", "ghcr.io", "--type", "ghcr",
		"--namespace", "myorg",
		"--tag-pattern", "semver", "--tag-pattern", "v*",
		"--auth-token-file", tokenFile,
		"--poll-interval-minutes", "30",
	)
	is.NoErr(err)

	is.Equal(got.Name, "ghcr")
	is.Equal(got.Url, "ghcr.io")
	is.Equal(string(got.Type), "ghcr")
	is.Equal(*got.Namespace, "myorg")
	is.Equal(*got.TagPatterns, []string{"semver", "v*"})
	// The token comes from the file, trimmed of its trailing newline.
	is.Equal(*got.AuthToken, "ghp_secret")
	is.Equal(*got.PollIntervalMinutes, int64(30))
	// Flags that were not given stay absent rather than arriving as zeroes.
	is.True(got.ScanMode == nil)
	is.True(got.Visibility == nil)
	is.True(got.IncludeUntagged == nil)
}

// A missing required flag fails before the client is ever built, so it is a
// usage error and not a request that goes out half-formed.
func TestRegistryCreateRequiresFlags(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		CreateRegistryFn: func(context.Context, client.CreateRegistryInputBody) (client.CreateRegistryResponseBody, error) {
			t.Fatal("create must not be called without --url")
			return client.CreateRegistryResponseBody{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "create", "--name", "ghcr", "--type", "ghcr")
	is.True(err != nil)
	is.Equal(exitCode(err, false), exitUsage)
}

func TestRegistryCreateMissingTokenFile(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		CreateRegistryFn: func(context.Context, client.CreateRegistryInputBody) (client.CreateRegistryResponseBody, error) {
			t.Fatal("create must not be called when a secret file is unreadable")
			return client.CreateRegistryResponseBody{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "create",
		"--name", "ghcr", "--url", "ghcr.io", "--type", "ghcr",
		"--auth-token-file", filepath.Join(t.TempDir(), "nope"))
	is.True(err != nil)
}

// TestRegistryUpdate is the read-modify-write contract: the PATCH body is a
// whole registry, so untouched settings must survive the round trip.
func TestRegistryUpdate(t *testing.T) {
	is := is.New(t)

	var got client.UpdateRegistryInputBody
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) {
			return testRegistry(), nil
		},
		UpdateRegistryFn: func(_ context.Context, id string, body client.UpdateRegistryInputBody) (client.RegistryResponse, error) {
			is.Equal(id, testRegistryID)
			got = body
			return testRegistry(), nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "update", testRegistryID,
		"--poll-interval-minutes", "15", "--enabled=false")
	is.NoErr(err)

	is.Equal(*got.PollIntervalMinutes, int64(15))
	is.Equal(got.Enabled, false)
	// Carried over untouched.
	is.Equal(got.Url, "ghcr.io")
	is.Equal(string(got.Type), "ghcr")
	is.Equal(string(*got.ScanMode), "poll")
	is.Equal(string(*got.Visibility), "private")
	is.Equal(string(*got.VerificationMode), "keyless")
	is.Equal(*got.Repositories, []string{"ocidex", "apko-cicd"})
	is.Equal(*got.IncludeUntagged, true)
}

// --enabled defaults to true, and a default must not silently re-enable a
// registry the user disabled earlier.
func TestRegistryUpdateLeavesEnabledAlone(t *testing.T) {
	is := is.New(t)

	current := testRegistry()
	current.Enabled = false

	var got client.UpdateRegistryInputBody
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) { return current, nil },
		UpdateRegistryFn: func(_ context.Context, _ string, body client.UpdateRegistryInputBody) (client.RegistryResponse, error) {
			got = body
			return current, nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "update", testRegistryID, "--url", "ghcr.io/v2")
	is.NoErr(err)
	is.Equal(got.Enabled, false)
	is.Equal(got.Url, "ghcr.io/v2")
}

func TestRegistryDelete(t *testing.T) {
	is := is.New(t)
	deleted := ""
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) { return testRegistry(), nil },
		DeleteRegistryFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	}

	stdout, _, err := runCLI(t, fake, "registry", "delete", testRegistryID, "--yes")
	is.NoErr(err)
	is.Equal(deleted, testRegistryID)
	is.True(strings.Contains(stdout, testRegistryID))
}

// Without --yes and without a terminal, delete refuses: a script that forgot
// the flag must fail rather than have the prompt answered by an empty stdin.
func TestRegistryDeleteWithoutConfirmation(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) { return testRegistry(), nil },
		DeleteRegistryFn: func(context.Context, string) error {
			t.Fatal("delete must not run unconfirmed")
			return nil
		},
	}

	_, _, err := runCLI(t, fake, "registry", "delete", testRegistryID)
	is.True(err != nil)
}

func TestRegistryScan(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetRegistryByNameFn: func(context.Context, string) (client.RegistryResponse, error) { return testRegistry(), nil },
		ScanRegistryFn: func(_ context.Context, id string) (client.ScanRegistryOutputBody, error) {
			is.Equal(id, testRegistryID)
			return client.ScanRegistryOutputBody{Message: "scan queued"}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "registry", "scan", "ghcr")
	is.NoErr(err)
	is.True(strings.Contains(stdout, "scan queued"))
}

// A missing registry must exit 3, not the generic failure code, so a script can
// tell "no such registry" from "the server is down".
func TestRegistryNotFoundExitCode(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetRegistryFn: func(context.Context, string) (client.RegistryResponse, error) {
			return client.RegistryResponse{}, client.ErrNotFound
		},
	}

	_, _, err := runCLI(t, fake, "registry", "get", testRegistryID)
	is.True(err != nil)
	is.Equal(exitCode(err, true), exitNotFound)
}
