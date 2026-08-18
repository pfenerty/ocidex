package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func TestToolErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains []string
	}{
		{
			name: "not found explains invisibility as well as absence",
			err:  client.ErrNotFound,
			// An agent that reads "not found" alone concludes the artifact does
			// not exist, when the API key may simply not be allowed to see it.
			contains: []string{"looking up thing", "no such resource", "cannot see"},
		},
		{
			name:     "forbidden names the scope needed",
			err:      client.ErrForbidden,
			contains: []string{"forbidden", "read-write"},
		},
		{
			name:     "bare conflict is distinct from a resolver conflict",
			err:      client.ErrConflict,
			contains: []string{"conflict", "already exists"},
		},
		{
			name:     "unauthorized points at the fix",
			err:      &client.APIError{Status: 401, Detail: "bad key"},
			contains: []string{"HTTP 401", "bad key", "ocidex-cli login"},
		},
		{
			name:     "bad request blames the arguments",
			err:      &client.APIError{Status: 422, Detail: "version is required"},
			contains: []string{"HTTP 422", "version is required", "re-read the tool's schema"},
		},
		{
			name:     "server error says retrying may help",
			err:      &client.APIError{Status: 503, Detail: "upstream down"},
			contains: []string{"HTTP 503", "server-side failure"},
		},
		{
			name:     "rate limit discourages an immediate retry",
			err:      &client.APIError{Status: 429, Detail: "slow down"},
			contains: []string{"HTTP 429", "retry after a pause"},
		},
		{
			name:     "transport failures are passed through verbatim",
			err:      fmt.Errorf("dial tcp 127.0.0.1:8080: connection refused"),
			contains: []string{"connection refused"},
		},
		{
			name:     "cancellation is not disguised as an API failure",
			err:      context.Canceled,
			contains: []string{"context canceled"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := is.New(t)
			got := toolError("looking up thing", tt.err)
			i.True(got != nil)
			for _, want := range tt.contains {
				if !strings.Contains(got.Error(), want) {
					t.Fatalf("message %q does not contain %q", got.Error(), want)
				}
			}
		})
	}
}

func TestToolErrorNilStaysNil(t *testing.T) {
	is.New(t).Equal(toolError("doing nothing", nil), nil)
}

// A 409 from an ADR-042 resolver is the one error an agent can act on
// mechanically, so the candidates have to survive into the message.
func TestToolErrorRendersLookupCandidates(t *testing.T) {
	i := is.New(t)

	err := toolError("looking up artifact nginx", &client.ConflictError{
		Detail: "3 artifacts named nginx",
		Candidates: []client.LookupCandidate{
			{Id: "id-a", Qualifiers: map[string]string{"type": "container", "group": "library"}},
			{Id: "id-b", Qualifiers: map[string]string{"type": "oci"}},
			{Id: "id-c"},
		},
	})

	msg := err.Error()
	i.True(strings.Contains(msg, "looking up artifact nginx"))
	i.True(strings.Contains(msg, "3 artifacts named nginx"))
	i.True(strings.Contains(msg, "id=id-a"))
	i.True(strings.Contains(msg, "id=id-c"))
	// Sorted, so two attempts at the same ambiguous lookup read identically
	// rather than differing by Go's map iteration order.
	i.True(strings.Contains(msg, "(group=library, type=container)"))
	// It unwraps, so callers testing the sentinel still work.
	i.True(errors.Is(err, client.ErrConflict))
}

// A resolver conflict with hundreds of matches means the question was far too
// broad; the advice must not be buried under the evidence.
func TestToolErrorTruncatesLongCandidateLists(t *testing.T) {
	i := is.New(t)

	candidates := make([]client.LookupCandidate, 25)
	for n := range candidates {
		candidates[n] = client.LookupCandidate{Id: fmt.Sprintf("id-%02d", n)}
	}

	msg := toolError("looking up artifact", &client.ConflictError{
		Detail:     "ambiguous",
		Candidates: candidates,
	}).Error()

	i.Equal(strings.Count(msg, "\n  - id="), maxListedCandidates)
	i.True(strings.Contains(msg, "and 15 more"))
}

// A 409 that is not a resolver conflict carries no candidates, and pkg/client
// gives back the bare sentinel for it.
func TestToolErrorConflictWithoutCandidates(t *testing.T) {
	i := is.New(t)

	msg := toolError("creating namespace", &client.ConflictError{Detail: "name taken"}).Error()
	i.True(strings.Contains(msg, "name taken"))
	i.True(strings.Contains(msg, "No candidates were returned"))
}
