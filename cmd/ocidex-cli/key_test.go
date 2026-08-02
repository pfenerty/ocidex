package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testKeyID = "77777777-7777-7777-7777-777777777777"

func TestKeyList(t *testing.T) {
	is := is.New(t)
	used := time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	fake := &client.FakeClient{
		ListAPIKeysFn: func(context.Context) ([]client.KeyMetaResponse, error) {
			return []client.KeyMetaResponse{
				{Id: testKeyID, Name: "ci", Prefix: "ocidex_a", Scope: "read-write",
					CreatedAt: used, LastUsedAt: &used},
				{Id: "other", Name: "laptop", Prefix: "ocidex_b", Scope: "read", CreatedAt: used},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "key", "list")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 3)
	is.True(strings.Contains(lines[1], "read-write"))
	// A key that has never been used is the one worth revoking, so the state
	// must be legible rather than an empty cell.
	is.True(strings.Contains(lines[2], "never"))
}

func TestKeyCreate(t *testing.T) {
	is := is.New(t)
	var got client.CreateAPIKeyInputBody
	fake := &client.FakeClient{
		CreateAPIKeyFn: func(_ context.Context, body client.CreateAPIKeyInputBody) (client.CreateAPIKeyOutputBody, error) {
			got = body
			return client.CreateAPIKeyOutputBody{Key: "ocidex_secretvalue"}, nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "key", "create", "--name", "ci", "--scope", "read-write")
	is.NoErr(err)
	is.Equal(got.Name, "ci")
	is.Equal(string(*got.Scope), "read-write")

	// The key alone on stdout: `key create > key.txt` must capture the key and
	// nothing else. The warning is guidance, so stderr.
	is.Equal(stdout, "ocidex_secretvalue\n")
	is.True(strings.Contains(stderr, "cannot be shown again"))
}

// An unset --scope stays absent rather than being sent as "", which would ask
// the server to validate an empty enum instead of applying its default.
func TestKeyCreateDefaultScope(t *testing.T) {
	is := is.New(t)
	var got client.CreateAPIKeyInputBody
	fake := &client.FakeClient{
		CreateAPIKeyFn: func(_ context.Context, body client.CreateAPIKeyInputBody) (client.CreateAPIKeyOutputBody, error) {
			got = body
			return client.CreateAPIKeyOutputBody{Key: "k"}, nil
		},
	}

	_, _, err := runCLI(t, fake, "key", "create", "--name", "ci")
	is.NoErr(err)
	is.True(got.Scope == nil)
}

func TestKeyCreateRejectsUnknownScope(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		CreateAPIKeyFn: func(context.Context, client.CreateAPIKeyInputBody) (client.CreateAPIKeyOutputBody, error) {
			called = true
			return client.CreateAPIKeyOutputBody{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "key", "create", "--name", "ci", "--scope", "write")
	is.True(err != nil)
	is.True(!called)
	is.True(strings.Contains(err.Error(), "read-write"))
}

func TestKeyCreateRequiresName(t *testing.T) {
	is := is.New(t)
	_, _, err := runCLI(t, &client.FakeClient{}, "key", "create")
	is.True(err != nil)
}

func TestKeyDelete(t *testing.T) {
	is := is.New(t)
	var gotID string
	fake := &client.FakeClient{
		DeleteAPIKeyFn: func(_ context.Context, id string) error {
			gotID = id
			return nil
		},
	}

	stdout, stderr, err := runCLI(t, fake, "key", "delete", testKeyID)
	is.NoErr(err)
	is.Equal(gotID, testKeyID)
	is.Equal(stdout, "")
	is.True(strings.Contains(stderr, "revoked"))
}

func TestKeyDeleteError(t *testing.T) {
	is := is.New(t)
	fake := &client.FakeClient{
		DeleteAPIKeyFn: func(context.Context, string) error { return errors.New("not found") },
	}

	_, _, err := runCLI(t, fake, "key", "delete", testKeyID)
	is.True(err != nil)
}
