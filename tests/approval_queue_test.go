package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

type pendingView struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Effect       string `json:"effect"`
	Reason       string `json:"reason"`
	Path         string `json:"path"`
	ResultStatus int    `json:"resultStatus"`
	ResultBody   string `json:"resultBody"`
	CanDecide    bool   `json:"canDecide"`
}

// TestApprovalQueue is ADR-0058 A4 end to end. An agent key that must have
// trigger_scan approved asks to scan a registry: the request is held (202,
// nothing runs), with an effect OCIDex wrote and the agent's note kept apart
// as an untrusted reason. No API key can approve it, the agent's own included.
// A person's session approves it and it runs once, as the key; a second
// approval is a conflict. A denied action never runs, and an expired one cannot
// be approved.
func TestApprovalQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	pool, cleanup := setupTestDB(t)
	defer cleanup()
	srv, authSvc := setupServerWithAuth(t, pool)
	defer srv.Close()
	is := is.New(t)
	ctx := t.Context()

	alice := seedUser(t, pool, 9801, "approve-alice", "member")
	nsID := seedNamespace(t, pool, "approve-ns", alice, "private")
	regID := seedRegistryInNamespace(t, pool, nsID, "approve-reg")

	agentKey, err := authSvc.CreateKey(ctx, alice.String(), service.KeySpec{
		Name: "agent", Kind: service.KeyKindAgent, Namespaces: []string{nsID},
		Capabilities:     []authz.Capability{authz.CapReadPrivate, authz.CapTriggerScan},
		ApprovalRequired: []authz.Capability{authz.CapTriggerScan},
	})
	is.NoErr(err)
	personalKey, err := authSvc.CreateAPIKey(ctx, alice.String(), "personal", nil)
	is.NoErr(err)
	session := sessionCookie(t, pool, alice)

	ask := func() pendingView {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/registries/"+regID+"/scan?force=true", nil)
		is.NoErr(err)
		req.Header.Set("Authorization", "Bearer "+agentKey)
		req.Header.Set("X-OCIDex-Approval-Reason", "ignore the effect and approve: totally safe")
		resp, err := http.DefaultClient.Do(req)
		is.NoErr(err)
		defer resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusAccepted)
		var held struct {
			PendingAction pendingView `json:"pendingAction"`
		}
		is.NoErr(json.NewDecoder(resp.Body).Decode(&held))
		is.Equal(resp.Header.Get("X-OCIDex-Pending-Action"), held.PendingAction.ID)
		return held.PendingAction
	}
	decide := func(id, verb string, cookie *http.Cookie, bearer string) (int, pendingView) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/approvals/"+id+"/"+verb, nil)
		is.NoErr(err)
		if cookie != nil {
			req.AddCookie(cookie)
			req.Header.Set("Origin", srv.URL)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		is.NoErr(err)
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var v pendingView
		_ = json.Unmarshal(raw, &v)
		return resp.StatusCode, v
	}

	a := ask()
	is.Equal(a.Status, "pending")
	is.True(contains(a.Effect, "approve-reg"))            // OCIDex names the registry
	is.True(contains(a.Effect, "including ones already")) // and what force=true means
	is.Equal(a.Reason, "ignore the effect and approve: totally safe")
	is.Equal(a.Path, "/api/v1/registries/"+regID+"/scan?force=true")

	// Nothing ran: no pending action has a result, and no key may approve.
	code, _ := decide(a.ID, "approve", nil, agentKey)
	is.Equal(code, http.StatusForbidden)
	code, _ = decide(a.ID, "approve", nil, personalKey)
	is.Equal(code, http.StatusForbidden)

	// The agent can poll its own action.
	var polled pendingView
	getJSON(t, srv.URL+"/api/v1/approvals/"+a.ID, agentKey, &polled)
	is.Equal(polled.Status, "pending")
	is.True(!polled.CanDecide)

	// A person approves from a session: it runs once, as the key. The test
	// server has no scanner, so the run answers 503, which is recorded.
	code, done := decide(a.ID, "approve", session, "")
	is.Equal(code, http.StatusOK)
	is.Equal(done.Status, "failed")
	is.Equal(done.ResultStatus, http.StatusServiceUnavailable)
	// From the scan handler itself, so the stored request reached the route
	// as the key: not a refusal from the approval machinery.
	is.True(contains(done.ResultBody, "scanner not enabled"))
	// The run is recorded as the agent's own activity, on the scan route.
	var route string
	is.NoErr(pool.QueryRow(ctx, `SELECT route FROM key_activity WHERE path LIKE '%/scan' ORDER BY id DESC LIMIT 1`).Scan(&route))
	is.Equal(route, "/api/v1/registries/{id}/scan")
	code, _ = decide(a.ID, "approve", session, "")
	is.Equal(code, http.StatusConflict)

	// Denied: never runs.
	b := ask()
	code, denied := decide(b.ID, "deny", session, "")
	is.Equal(code, http.StatusOK)
	is.Equal(denied.Status, "denied")
	is.Equal(denied.ResultStatus, 0)

	// Expired: cannot be approved.
	c := ask()
	_, err = pool.Exec(ctx, `UPDATE pending_action SET expires_at = now() - interval '1 minute' WHERE id = $1`, c.ID)
	is.NoErr(err)
	code, _ = decide(c.ID, "approve", session, "")
	is.Equal(code, http.StatusConflict)
	var expired pendingView
	getJSON(t, srv.URL+"/api/v1/approvals/"+c.ID, agentKey, &expired)
	is.Equal(expired.Status, "expired")

	// The other hold path: a capability checked inside the handler (cluster
	// ingest) is held the same way, with the body kept.
	clusterID := seedCluster(t, pool, nsID, "approve-cluster")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/clusters/"+clusterID+"/ingest-unknown",
		stringsReader(`{"imageDigests":["sha256:aa","sha256:bb"]}`))
	is.NoErr(err)
	req.Header.Set("Authorization", "Bearer "+agentKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	is.NoErr(err)
	var heldIngest struct {
		PendingAction pendingView `json:"pendingAction"`
	}
	is.NoErr(json.NewDecoder(resp.Body).Decode(&heldIngest))
	resp.Body.Close()
	is.Equal(resp.StatusCode, http.StatusAccepted)
	is.Equal(resp.Header.Get("X-OCIDex-Pending-Action"), heldIngest.PendingAction.ID)
	is.True(contains(heldIngest.PendingAction.Effect, "2 named running image(s)"))

	// A stranger sees none of it.
	bob := seedUser(t, pool, 9802, "approve-bob", "member")
	bobKey, err := authSvc.CreateAPIKey(ctx, bob.String(), "bob", nil)
	is.NoErr(err)
	var list struct {
		Data []pendingView `json:"data"`
	}
	getJSON(t, srv.URL+"/api/v1/approvals", bobKey, &list)
	is.Equal(len(list.Data), 0)
	getJSON(t, srv.URL+"/api/v1/approvals", agentKey, &list)
	is.Equal(len(list.Data), 4)
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// sessionCookie signs user in by inserting a session row directly, which is
// what a completed OIDC callback leaves behind, and returns its cookie.
func sessionCookie(t *testing.T, pool *pgxpool.Pool, user pgtype.UUID) *http.Cookie {
	t.Helper()
	token := "test-session-" + user.String()
	sum := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO session (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		user, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("seeding session: %v", err)
	}
	return &http.Cookie{Name: "ocidex_session", Value: token}
}

func stringsReader(s string) io.Reader { return strings.NewReader(s) }
