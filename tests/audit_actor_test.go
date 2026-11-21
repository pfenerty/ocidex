package tests

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/audit"
	"github.com/pfenerty/ocidex/internal/event"
)

// syncBuffer is a bytes.Buffer safe to write from the server's goroutines and
// read from the test's.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type auditLine struct {
	Msg        string            `json:"msg"`
	EventType  string            `json:"event_type"`
	ResourceID string            `json:"resource_id"`
	Actor      map[string]string `json:"actor"`
}

func auditLines(t *testing.T, out string) []auditLine {
	t.Helper()
	var lines []auditLine
	for _, raw := range strings.Split(strings.TrimSpace(out), "\n") {
		var l auditLine
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("decoding log line %q: %v", raw, err)
		}
		if l.Msg == "audit" {
			lines = append(lines, l)
		}
	}
	return lines
}

// An SBOM uploaded and deleted through the API with an API key is audited
// with the user and the key as its actor (ocidex-n9na).
func TestAuditLineNamesAPIKeyActor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	var out syncBuffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))
	bus := event.NewBus(logger)
	is := is.New(t)
	is.NoErr(audit.NewExtension(logger).Init(bus))

	srv, authSvc, _ := setupServerWithPublisher(t, pool, bus)
	defer srv.Close()

	ctx := t.Context()
	userID := seedUser(t, pool, 7801, "auditor", "member")
	key, err := authSvc.CreateAPIKey(ctx, userID.String(), "ci", nil)
	is.NoErr(err)
	var keyID pgtype.UUID
	is.NoErr(pool.QueryRow(ctx, `SELECT id FROM api_key WHERE user_id = $1`, userID).Scan(&keyID))

	ns := seedNamespace(t, pool, "audit-ns", userID, "private")
	src := seedSource(t, pool, ns, "upload", "ci")
	sbomID := mustIngest(t, srv.URL, "/api/v1/sboms?source="+src, minimalSBOM, key)

	resp, err := doWithAuth(t, http.MethodDelete, srv.URL+"/api/v1/sboms/"+sbomID, "", key)
	is.NoErr(err)
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusNoContent)

	want := map[string]string{"kind": "user", "id": userID.String(), "api_key_id": keyID.String()}
	seen := map[string]bool{}
	for _, l := range auditLines(t, out.String()) {
		if l.ResourceID != sbomID {
			continue
		}
		is.Equal(l.Actor, want) // every audit line for this SBOM names the key's user and the key
		seen[l.EventType] = true
	}
	is.True(seen["sbom.ingested"])
	is.True(seen["sbom.deleted"])
}
