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
			narrow := []string{"ingest"}
			return []client.KeyMetaResponse{
				{Id: testKeyID, Name: "ci", Prefix: "ocidex_a", Capabilities: &narrow,
					CreatedAt: used, LastUsedAt: &used},
				{Id: "other", Name: "laptop", Prefix: "ocidex_b", Capabilities: &keyCapabilities, CreatedAt: used},
			}, nil
		},
	}

	stdout, _, err := runCLI(t, fake, "key", "list")
	is.NoErr(err)

	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	is.Equal(len(lines), 3)
	is.True(strings.Contains(lines[1], "ingest"))
	// A key holding every capability collapses to a word: ten comma-separated
	// names in a table cell is not information.
	is.True(strings.Contains(lines[2], "all"))
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

	stdout, stderr, err := runCLI(t, fake, "key", "create",
		"--name", "ci", "--capability", "ingest", "--capability", "read_private")
	is.NoErr(err)
	is.Equal(got.Name, "ci")
	is.Equal(*got.Capabilities, []client.CreateAPIKeyInputBodyCapabilities{
		client.Ingest, client.ReadPrivate,
	})

	// The key alone on stdout: `key create > key.txt` must capture the key and
	// nothing else. The warning is guidance, so stderr.
	is.Equal(stdout, "ocidex_secretvalue\n")
	is.True(strings.Contains(stderr, "cannot be shown again"))
}

// An unnamed capability set stays absent rather than being sent as an empty
// list. Both mean "all of them" to the server today, but sending nothing keeps
// the server's default the single definition of that.
func TestKeyCreateDefaultCapabilities(t *testing.T) {
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
	is.True(got.Capabilities == nil)
}

func TestKeyCreateRejectsUnknownCapability(t *testing.T) {
	is := is.New(t)
	called := false
	fake := &client.FakeClient{
		CreateAPIKeyFn: func(context.Context, client.CreateAPIKeyInputBody) (client.CreateAPIKeyOutputBody, error) {
			called = true
			return client.CreateAPIKeyOutputBody{}, nil
		},
	}

	_, _, err := runCLI(t, fake, "key", "create", "--name", "ci", "--capability", "write")
	is.True(err != nil)
	is.True(!called)
	// The error names the vocabulary — a rejected typo should not send the
	// caller to the docs to find out what was allowed.
	is.True(strings.Contains(err.Error(), "read_private"))
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
