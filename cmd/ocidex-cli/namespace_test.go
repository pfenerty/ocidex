package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testNamespaceID = "33333333-3333-3333-3333-333333333333"

func testNamespace() client.NamespaceResponse {
	owner := "octocat"
	return client.NamespaceResponse{
		Id:            testNamespaceID,
		Name:          "acme",
		Visibility:    "private",
		OwnerUsername: &owner,
		CreatedAt:     "2026-07-01T09:00:00Z",
		UpdatedAt:     "2026-07-02T09:00:00Z",
	}
}

func TestNamespaceList(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		ListNamespacesFn: func(context.Context) ([]client.NamespaceResponse, error) {
			return []client.NamespaceResponse{testNamespace()}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "namespace", "list")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 2)
	is.True(strings.Contains(lines[0], "VISIBILITY"))
	is.True(strings.Contains(lines[1], "acme"))
	is.True(strings.Contains(lines[1], "private"))
	is.True(strings.Contains(lines[1], "octocat"))
}

func TestNamespaceGetJSON(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetNamespaceFn: func(_ context.Context, id string) (client.NamespaceResponse, error) {
			is.Equal(id, testNamespaceID)
			return testNamespace(), nil
		},
	}

	stdout, _, err := runCLI(t, fake, "namespace", "get", testNamespaceID, "-o", "json")
	is.NoErr(err)

	var got client.NamespaceResponse
	is.NoErr(json.Unmarshal([]byte(stdout), &got))
	is.Equal(got.Name, "acme")
}

// A non-UUID reference is resolved by name, and is not sent to the by-id
// endpoint where it would 404 as a malformed uuid.
func TestNamespaceGetByName(t *testing.T) {
	is := is.New(t)
	called := ""
	fake := &client.FakeClient{
		GetNamespaceFn: func(context.Context, string) (client.NamespaceResponse, error) {
			t.Fatal("a name must not be sent to the by-id endpoint")
			return client.NamespaceResponse{}, nil
		},
		GetNamespaceByNameFn: func(_ context.Context, name string) (client.NamespaceResponse, error) {
			called = name
			return testNamespace(), nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "get", "acme")
	is.NoErr(err)
	is.Equal(called, "acme")
}

func TestNamespaceCreate(t *testing.T) {
	is := is.New(t)

	var got client.CreateNamespaceInputBody
	fake := &client.FakeClient{
		CreateNamespaceFn: func(_ context.Context, body client.CreateNamespaceInputBody) (client.NamespaceResponse, error) {
			got = body
			return testNamespace(), nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "create", "--name", "acme", "--visibility", "public")
	is.NoErr(err)
	is.Equal(got.Name, "acme")
	is.Equal(string(*got.Visibility), "public")
}

// Visibility is omit-to-default: the server, not the CLI, decides that an
// unspecified namespace is private.
func TestNamespaceCreateOmitsUnsetVisibility(t *testing.T) {
	is := is.New(t)

	var got client.CreateNamespaceInputBody
	fake := &client.FakeClient{
		CreateNamespaceFn: func(_ context.Context, body client.CreateNamespaceInputBody) (client.NamespaceResponse, error) {
			got = body
			return testNamespace(), nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "create", "--name", "acme")
	is.NoErr(err)
	is.True(got.Visibility == nil)
}

func TestNamespaceCreateRequiresName(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		CreateNamespaceFn: func(context.Context, client.CreateNamespaceInputBody) (client.NamespaceResponse, error) {
			t.Fatal("create must not be called without --name")
			return client.NamespaceResponse{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "create")
	is.True(err != nil)
	is.Equal(exitCode(err, false), exitUsage)
}

// Only the flags actually given are sent: the PATCH is omit-to-keep, so
// including an unset field would silently reset it.
func TestNamespaceUpdateSendsOnlyChangedFields(t *testing.T) {
	is := is.New(t)

	var got client.UpdateNamespaceInputBody
	fake := &client.FakeClient{
		GetNamespaceByNameFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return testNamespace(), nil
		},
		UpdateNamespaceFn: func(_ context.Context, id string, body client.UpdateNamespaceInputBody) (client.NamespaceResponse, error) {
			is.Equal(id, testNamespaceID)
			got = body
			return testNamespace(), nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "update", "acme", "--visibility", "public")
	is.NoErr(err)
	is.True(got.Name == nil)
	is.Equal(string(*got.Visibility), "public")
}

// An update with no flags is a no-op request that would still count as a write;
// it is rejected as a usage error instead.
func TestNamespaceUpdateRequiresAField(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetNamespaceFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return testNamespace(), nil
		},
		UpdateNamespaceFn: func(context.Context, string, client.UpdateNamespaceInputBody) (client.NamespaceResponse, error) {
			t.Fatal("update must not be called with nothing to change")
			return client.NamespaceResponse{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "update", testNamespaceID)
	is.True(err != nil)
	is.Equal(exitCode(err, true), exitUsage)
}

func TestNamespaceDelete(t *testing.T) {
	is := is.New(t)
	deleted := ""
	fake := &client.FakeClient{
		GetNamespaceFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return testNamespace(), nil
		},
		DeleteNamespaceFn: func(_ context.Context, id string) error {
			deleted = id
			return nil
		},
	}

	stdout, _, err := runCLI(t, fake, "namespace", "delete", testNamespaceID, "--yes")
	is.NoErr(err)
	is.Equal(deleted, testNamespaceID)
	is.True(strings.Contains(stdout, testNamespaceID))
}

// The confirmation names what goes with the namespace, because deleting one
// takes its sources and their artifacts too.
func TestNamespaceDeleteNamesTheBlastRadius(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetNamespaceFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return testNamespace(), nil
		},
		DeleteNamespaceFn: func(context.Context, string) error {
			t.Fatal("delete must not run unconfirmed")
			return nil
		},
	}

	_, stderr, err := runCLI(t, fake, "namespace", "delete", testNamespaceID)
	is.True(err != nil)
	is.True(strings.Contains(err.Error()+stderr, "everything ingested under them"))
}

func TestNamespaceNotFoundExitCode(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		GetNamespaceByNameFn: func(context.Context, string) (client.NamespaceResponse, error) {
			return client.NamespaceResponse{}, client.ErrNotFound
		},
	}

	_, _, err := runCLI(t, fake, "namespace", "get", "nope")
	is.True(err != nil)
	is.Equal(exitCode(err, true), exitNotFound)
}
