package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pfenerty/ocidex/pkg/client"
)

// maxListedCandidates bounds how many rows a 409 message spells out. A resolver
// conflict with hundreds of matches means the agent asked far too broad a
// question; printing all of them would bury the advice under the evidence.
const maxListedCandidates = 10

// toolError turns a pkg/client error into the message an agent sees.
//
// The SDK already routes a handler's error to CallToolResult.IsError, so the
// channel is not in question here — the wording is. A model reads the message
// and decides what to do next, so each branch says what happened *and* what
// would work instead. "HTTP 409: ambiguous" tells it nothing; the candidate list
// below tells it exactly which qualifier to add.
//
// action is the operation in progress, phrased as a noun ("looking up artifact
// nginx"), and is prefixed to every message.
func toolError(action string, err error) error {
	if err == nil {
		return nil
	}

	// Every branch wraps with %w rather than reformatting: pkg/client's typed
	// errors have to survive the trip so that a caller — a tool that treats a
	// 404 as an empty result, say — can still test the sentinel.
	var conflict *client.ConflictError
	if errors.As(err, &conflict) {
		return fmt.Errorf("%s: %w\n%s", action, err, describeCandidates(conflict.Candidates))
	}

	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s: %w%s", action, err, hintForStatus(apiErr.Status))
	}

	switch {
	case errors.Is(err, client.ErrNotFound):
		return fmt.Errorf("%s: %w — no such resource, or it is in a namespace this API key cannot see", action, err)
	case errors.Is(err, client.ErrForbidden):
		return fmt.Errorf("%s: %w — the API key lacks the scope for this call "+
			"(read endpoints need `read`, writes need `read-write`)", action, err)
	case errors.Is(err, client.ErrConflict):
		return fmt.Errorf("%s: %w — the resource already exists or is in a state that forbids this call", action, err)
	default:
		// Transport failures land here: connection refused, DNS, TLS, a
		// cancelled context. The cause is the whole message and is worth
		// showing verbatim.
		return fmt.Errorf("%s: %w", action, err)
	}
}

// hintForStatus adds the one thing a status code implies that the server's own
// detail string usually omits: whose problem it is, and what to do next.
func hintForStatus(status int) string {
	switch {
	case status == 401:
		return " — the API key was rejected; re-run `ocidex-cli login`"
	case status == 400 || status == 422:
		return " — the arguments were rejected; re-read the tool's schema"
	case status == 429:
		return " — rate limited; retry after a pause rather than immediately"
	case status >= 500:
		return " — server-side failure, not a bad request; retrying may help"
	default:
		return ""
	}
}

// describeCandidates renders an ADR-042 candidate list as the disambiguation
// advice it is meant to be: each row names the qualifiers that separate it, so
// the next call can pass one of them.
func describeCandidates(candidates []client.LookupCandidate) string {
	if len(candidates) == 0 {
		return "No candidates were returned; narrow the query and retry."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d candidates — retry with one more qualifier, or call again with the id directly:",
		len(candidates))

	shown := candidates
	if len(shown) > maxListedCandidates {
		shown = shown[:maxListedCandidates]
	}
	for _, c := range shown {
		fmt.Fprintf(&b, "\n  - id=%s%s", c.Id, formatQualifiers(c.Qualifiers))
	}
	if len(candidates) > len(shown) {
		fmt.Fprintf(&b, "\n  ... and %d more", len(candidates)-len(shown))
	}
	return b.String()
}

// formatQualifiers sorts by key so the same conflict reads the same way twice —
// Go randomises map iteration, and an agent comparing two attempts should not
// see the difference as meaningful.
func formatQualifiers(q map[string]string) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, q[k]))
	}
	return " (" + strings.Join(parts, ", ") + ")"
}
