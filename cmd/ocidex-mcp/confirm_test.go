package main

import (
	"context"
	"testing"

	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// connectEliciting connects a client that answers every elicitation with
// action, and counts the prompts it was shown.
func connectEliciting(t *testing.T, api client.Client, action string, asked *int) *mcp.ClientSession {
	t.Helper()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := t.Context()
	ss, err := newServer(api, testServerURL).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connecting server: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, &mcp.ClientOptions{
		ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			*asked++
			return &mcp.ElicitResult{Action: action}, nil
		},
	})
	session, err := c.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connecting client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// watchCounter is a FakeClient whose watch calls are counted.
func watchCounter(caps, approval []string, calls *int) *client.FakeClient {
	return &client.FakeClient{
		GetKeySelfFn: agentSelf(caps, approval),
		WatchArtifactFn: func(context.Context, string, client.WriteOpts) (client.WriteResult, error) {
			*calls++
			return client.WriteResult{}, nil
		},
		RequestRegistryScanFn: func(context.Context, string, bool, client.WriteOpts) (client.WriteResult, error) {
			*calls++
			return client.WriteResult{}, nil
		},
	}
}

func TestElicitationGatesWrites(t *testing.T) {
	for _, tc := range []struct {
		action, status string
		sent           int
	}{
		{"accept", "done", 1},
		{"decline", statusDeclined, 0},
		{"cancel", statusCancelled, 0},
	} {
		t.Run(tc.action, func(t *testing.T) {
			i := is.New(t)
			var asked, calls int
			session := connectEliciting(t, watchCounter([]string{"read_private"}, nil, &calls), tc.action, &asked)
			// A model-set "confirm" is not consent: the user is still asked.
			res := callTool(t, session, "ocidex_watch_artifact", map[string]any{"artifact_id": "a1", "confirm": true})
			if res.IsError {
				// The schema refusing unknown arguments is an acceptable answer too;
				// retry without it so the elicitation path is still exercised.
				res = callTool(t, session, "ocidex_watch_artifact", map[string]any{"artifact_id": "a1"})
			}
			i.Equal(writeOut(t, res).Status, tc.status)
			i.Equal(asked, 1)
			i.Equal(calls, tc.sent)
		})
	}
}

// A client without elicitation gets the write; the key's limits still apply.
func TestNoElicitationFallsBack(t *testing.T) {
	i := is.New(t)
	var calls int
	out := writeOut(t, callTool(t, connect(t, watchCounter([]string{"read_private"}, nil, &calls)), "ocidex_watch_artifact", map[string]any{"artifact_id": "a1"}))
	i.Equal(out.Status, "done")
	i.Equal(calls, 1)
}

// A write the server holds is not put to the user here: a person approves it
// in OCIDex instead. Preview never asks.
func TestHeldAndPreviewWritesDoNotElicit(t *testing.T) {
	i := is.New(t)
	var asked, calls int
	session := connectEliciting(t, watchCounter([]string{"read_private", "trigger_scan"}, []string{"trigger_scan"}, &calls), "decline", &asked)
	callTool(t, session, "ocidex_scan_registry", map[string]any{"registry_id": "r1"})
	callTool(t, session, "ocidex_watch_artifact", map[string]any{"artifact_id": "a1", "preview": true})
	i.Equal(asked, 0)
	i.Equal(calls, 1) // the held-capable scan went to the server
}
