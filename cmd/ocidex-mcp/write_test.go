package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

func toolNames(t *testing.T, session *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := session.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("listing tools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func writeOut(t *testing.T, res *mcp.CallToolResult) writeOutcome {
	t.Helper()
	var out writeOutcome
	if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
		t.Fatalf("decoding %q: %v", resultText(res), err)
	}
	return out
}

// Write tools exist only for an agent key that may use them (ADR-0058 A8).
func TestWriteToolsFollowTheKey(t *testing.T) {
	i := is.New(t)

	personal := toolNames(t, connect(t, &client.FakeClient{}))
	i.True(!personal["ocidex_watch_artifact"])
	i.True(!personal["ocidex_scan_registry"])

	analyst := toolNames(t, connect(t, &client.FakeClient{GetKeySelfFn: agentSelf([]string{"read_private"}, nil)}))
	i.True(analyst["ocidex_watch_artifact"]) // own watchlist: no capability needed
	i.True(analyst["ocidex_approval_status"])
	i.True(!analyst["ocidex_scan_registry"])
	i.True(!analyst["ocidex_ingest_unknown_images"])

	coverage := toolNames(t, connect(t, &client.FakeClient{GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan"}, []string{"trigger_scan"})}))
	i.True(coverage["ocidex_scan_registry"])
	i.True(coverage["ocidex_ingest_unknown_images"])
}

// A held scan is reported as held, with the server's effect, the approval id
// and the link a person uses, and the agent is told not to resend.
func TestScanRegistryHeld(t *testing.T) {
	i := is.New(t)
	id := uuid.New()
	var gotReason, gotTool string
	api := &client.FakeClient{
		GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan"}, []string{"trigger_scan"}),
		RequestRegistryScanFn: func(_ context.Context, _ string, _ bool, w client.WriteOpts) (client.WriteResult, error) {
			gotReason, gotTool = w.Reason, w.Tool
			return client.WriteResult{Held: &client.PendingActionView{Id: id, Effect: "Scan registry quay.io in namespace local", Status: "pending"}}, nil
		},
	}
	out := writeOut(t, callTool(t, connect(t, api), "ocidex_scan_registry", map[string]any{"registry_id": "r1", "reason": "gap"}))
	i.Equal(out.Status, "held")
	i.Equal(out.Effect, "Scan registry quay.io in namespace local")
	i.Equal(out.ApprovalID, id.String())
	i.Equal(out.ApprovalURL, testServerURL+"/approvals/"+id.String())
	i.True(out.Next != "")
	i.Equal(gotReason, "gap")
	i.Equal(gotTool, "ocidex_scan_registry")
}

// Preview sends nothing.
func TestWritePreviewSendsNothing(t *testing.T) {
	i := is.New(t)
	called := false
	api := &client.FakeClient{
		GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan"}, nil),
		RequestClusterIngestFn: func(context.Context, string, []string, client.WriteOpts) (client.WriteResult, error) {
			called = true
			return client.WriteResult{}, nil
		},
	}
	out := writeOut(t, callTool(t, connect(t, api), "ocidex_ingest_unknown_images",
		map[string]any{"cluster_id": "c1", "image_digests": []string{"sha256:aa"}, "preview": true}))
	i.Equal(out.Status, "preview")
	i.True(!called)
}

// Allowed writes report done; refusals (permission, budget) come back as tool
// errors carrying the server's reason.
func TestWriteDoneAndRefused(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{
		GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan"}, nil),
		WatchArtifactFn: func(context.Context, string, client.WriteOpts) (client.WriteResult, error) {
			return client.WriteResult{}, nil
		},
		UnwatchArtifactFn: func(context.Context, string, client.WriteOpts) (client.WriteResult, error) {
			return client.WriteResult{}, &client.APIError{Status: http.StatusForbidden, Detail: "denied by the namespace"}
		},
		RequestRegistryScanFn: func(context.Context, string, bool, client.WriteOpts) (client.WriteResult, error) {
			return client.WriteResult{}, &client.APIError{Status: http.StatusTooManyRequests, Detail: "this agent key has used its scans budget for the hour"}
		},
	}
	session := connect(t, api)
	i.Equal(writeOut(t, callTool(t, session, "ocidex_watch_artifact", map[string]any{"artifact_id": "a1"})).Status, "done")

	res := callTool(t, session, "ocidex_unwatch_artifact", map[string]any{"artifact_id": "a1"})
	i.True(res.IsError)

	res = callTool(t, session, "ocidex_scan_registry", map[string]any{"registry_id": "r1"})
	i.True(res.IsError)
	i.True(strings.Contains(resultText(res), "budget"))
}

// approval_status reports the outcome and what to do next.
func TestApprovalStatus(t *testing.T) {
	i := is.New(t)
	code := int64(202)
	api := &client.FakeClient{
		GetKeySelfFn: agentSelf([]string{"read_private"}, nil),
		GetPendingActionFn: func(context.Context, string) (client.PendingActionView, error) {
			return client.PendingActionView{Status: "denied", Effect: "x", ResultStatus: &code}, nil
		},
	}
	var out approvalOutput
	i.NoErr(json.Unmarshal([]byte(resultText(callTool(t, connect(t, api), "ocidex_approval_status", map[string]any{"approval_id": "p1"}))), &out))
	i.Equal(out.Status, "denied")
	i.True(out.Next != "")
}
