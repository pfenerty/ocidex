package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testSourceID = "44444444-4444-4444-4444-444444444444"

func testSource() client.SourceResponse {
	nsName := "acme"
	return client.SourceResponse{
		Id:            testSourceID,
		Name:          "ci-uploads",
		Kind:          "upload",
		NamespaceId:   testNamespaceID,
		NamespaceName: &nsName,
		CreatedAt:     "2026-07-01T09:00:00Z",
		UpdatedAt:     "2026-07-02T09:00:00Z",
	}
}

func TestSourceList(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListSourcesFn: func(_ context.Context, namespaceID string) ([]client.SourceResponse, error) {
			is.Equal(namespaceID, "")
			return []client.SourceResponse{testSource()}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "source", "list")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[0], "KIND"))
	// The id leads, because it is the only handle get/update/delete take.
	is.True(strings.HasPrefix(lines[1], testSourceID))
	is.True(strings.Contains(lines[1], "ci-uploads"))
	is.True(strings.Contains(lines[1], "acme"))
}

// --namespace takes a name, and it is resolved to an id before the list call:
// the API filters on namespace_id only.
func TestSourceListByNamespaceName(t *testing.T) {
	is := is.New(t)
	scoped := ""
	fake := &client.FakeClient{
		GetNamespaceByNameFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return testNamespace(), nil
		},
		ListSourcesFn: func(_ context.Context, namespaceID string) ([]client.SourceResponse, error) {
			scoped = namespaceID
			return []client.SourceResponse{testSource()}, nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "list", "--namespace", "acme")
	is.NoErr(err)
	is.Equal(scoped, testNamespaceID)
}

func TestSourceGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSourceFn: func(_ context.Context, id string) (client.SourceResponse, error) {
			is.Equal(id, testSourceID)
			return testSource(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "source", "get", testSourceID, "-o", "json")
	is.NoErr(err)

	var got client.SourceResponse
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.Name, "ci-uploads")
}

// Source names are unique only within a namespace, so there is no by-name
// endpoint to fall back to: a name is a usage error, not a lookup.
func TestSourceGetRejectsAName(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSourceFn: func(context.Context, string) (client.SourceResponse, error) {
			t.Fatal("a name must not be sent to the by-id endpoint")
			return client.SourceResponse{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "get", "ci-uploads")
	is.True(err != nil)
	is.Equal(exitCode(err, true), exitUsage)
}

func TestSourceCreate(t *testing.T) {
	is := is.New(t)

	var got client.CreateSourceInputBody
	fake := &client.FakeClient{
		GetNamespaceByNameFn: func(_ context.Context, name string) (client.NamespaceResponse, error) {
			is.Equal(name, "acme")
			return testNamespace(), nil
		},
		CreateSourceFn: func(_ context.Context, body client.CreateSourceInputBody) (client.SourceResponse, error) {
			got = body
			return testSource(), nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "create", "--name", "ci-uploads", "--namespace", "acme")
	is.NoErr(err)
	is.Equal(got.Name, "ci-uploads")
	is.Equal(got.NamespaceId.String(), testNamespaceID)
}

func TestSourceCreateRequiresNamespace(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		CreateSourceFn: func(context.Context, client.CreateSourceInputBody) (client.SourceResponse, error) {
			t.Fatal("create must not be called without --namespace")
			return client.SourceResponse{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "create", "--name", "ci-uploads")
	is.True(err != nil)
	is.Equal(exitCode(err, false), exitUsage)
}

func TestSourceUpdate(t *testing.T) {
	is := is.New(t)

	var got client.UpdateSourceInputBody
	fake := &client.FakeClient{
		GetSourceFn: func(context.Context, string) (client.SourceResponse, error) { return testSource(), nil },
		UpdateSourceFn: func(_ context.Context, id string, body client.UpdateSourceInputBody) (client.SourceResponse, error) {
			is.Equal(id, testSourceID)
			got = body
			return testSource(), nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "update", testSourceID, "--name", "ci-uploads-2")
	is.NoErr(err)
	is.Equal(got.Name, "ci-uploads-2")
}

func TestSourceDelete(t *testing.T) {
	is := is.New(t)
	deleted := ""
	fake := &client.FakeClient{
		GetSourceFn: func(context.Context, string) (client.SourceResponse, error) { return testSource(), nil },
		DeleteSourceFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	}

	stdout, _, err := runCLI(t, fake, "source", "delete", testSourceID, "--yes")
	is.NoErr(err)
	is.Equal(deleted, testSourceID)
	is.True(strings.Contains(stdout, testSourceID))
}

// Without --yes and without a terminal, the delete refuses rather than reading
// the empty stdin a script would hand it as consent.
func TestSourceDeleteWithoutConfirmation(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSourceFn: func(context.Context, string) (client.SourceResponse, error) { return testSource(), nil },
		DeleteSourceFn: func(context.Context, string) error {
			t.Fatal("delete must not run unconfirmed")
			return nil
		},
	}

	_, _, err := runCLI(t, fake, "source", "delete", testSourceID)
	is.True(err != nil)
}

func TestSourceNotFoundExitCode(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetSourceFn: func(context.Context, string) (client.SourceResponse, error) {
			return client.SourceResponse{}, client.ErrNotFound
		},
	}

	_, _, err := runCLI(t, fake, "source", "get", testSourceID)
	is.True(err != nil)
	is.Equal(exitCode(err, true), exitNotFound)
}
