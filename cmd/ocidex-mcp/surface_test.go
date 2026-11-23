package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

func agentSelf(caps, approval []string) func(context.Context) (client.KeySelfOutputBody, error) {
	return func(context.Context) (client.KeySelfOutputBody, error) {
		ns := []string{"n1111111-1111-1111-1111-111111111111"}
		return client.KeySelfOutputBody{Kind: "agent", Capabilities: &caps, ApprovalRequired: &approval, Namespaces: &ns}, nil
	}
}

// whoami tells an agent what its key may do, so it can plan before it acts.
func TestWhoamiReportsTheKeySurface(t *testing.T) {
	i := is.New(t)
	api := &client.FakeClient{GetKeySelfFn: agentSelf([]string{"read_private", "trigger_scan"}, []string{"trigger_scan"})}
	res := callTool(t, connect(t, api), "ocidex_whoami", nil)
	i.True(!res.IsError)
	var out whoamiOutput
	i.NoErr(json.Unmarshal([]byte(resultText(res)), &out))
	i.Equal(out.KeyKind, "agent")
	i.Equal(out.Capabilities, []string{"read_private", "trigger_scan"})
	i.Equal(out.ApprovalRequired, []string{"trigger_scan"})
	i.Equal(len(out.Namespaces), 1)
	i.True(out.WriteTools)
	i.Equal(out.Hint, "")
}

// A personal key, the CLI's login key, keeps the read-only surface and is told
// how to get more.
func TestPersonalKeyIsReadOnly(t *testing.T) {
	i := is.New(t)
	res := callTool(t, connect(t, &client.FakeClient{}), "ocidex_whoami", nil)
	var out whoamiOutput
	i.NoErr(json.Unmarshal([]byte(resultText(res)), &out))
	i.Equal(out.KeyKind, "personal")
	i.True(!out.WriteTools)
	i.True(out.Hint != "")
}

func TestSurfaceGates(t *testing.T) {
	i := is.New(t)
	agent := keySurface{kind: "agent", capabilities: []string{"read_private"}, approvalRequired: []string{"trigger_scan"}}
	i.True(agent.allows(""))              // a write needing no capability (own watchlist)
	i.True(!agent.allows("trigger_scan")) // not carried
	i.True(agent.held("trigger_scan"))
	personal := keySurface{kind: "personal", capabilities: []string{"read_private", "trigger_scan"}}
	i.True(!personal.allows(""))
	i.True(!personal.allows("trigger_scan"))
}
