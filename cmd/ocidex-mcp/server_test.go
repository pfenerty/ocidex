package main

import (
	"context"
	"strings"
	"testing"

	"github.com/matryer/is"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

const testServerURL = "https://ocidex.test"

// connect wires a client to the server under test over the SDK's in-memory
// transport pair.
//
// This is the real protocol path — initialize handshake, JSON-RPC framing,
// schema validation of tool arguments — with only the pipe swapped out, so a
// tool whose schema the SDK would reject fails here rather than in front of a
// user. The API underneath is a FakeClient, so no OCIDex server is involved.
func connect(t *testing.T, api client.Client) *mcp.ClientSession {
	t.Helper()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := t.Context()

	serverSession, err := newServer(api, testServerURL).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("connecting server: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil).
		Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("connecting client: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session
}

// callTool is the happy-path caller: it fails the test on a protocol error but
// returns tool errors, which are results rather than errors.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("calling %s: %v", name, err)
	}
	return res
}

// resultText flattens a tool result's content, which is where both the rendered
// output and any error message land.
func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String()
}

// The handshake and the tool list are what an MCP client does before it ever
// calls a tool; a server that fails either is invisible to the model.
func TestServerHandshakeAndToolListing(t *testing.T) {
	i := is.New(t)
	session := connect(t, &client.FakeClient{})

	init := session.InitializeResult()
	i.Equal(init.ServerInfo.Name, serverName)
	i.True(init.Instructions != "") // the model's only orientation before choosing a tool

	tools, err := session.ListTools(t.Context(), nil)
	i.NoErr(err)
	i.True(len(tools.Tools) > 0)

	for _, tool := range tools.Tools {
		// A tool without a description is one the model must guess about.
		i.True(tool.Description != "")
		i.True(tool.InputSchema != nil)
		// Namespaced so that a client with several servers connected does not
		// see a bare `whoami` and have to infer whose it is.
		i.True(strings.HasPrefix(tool.Name, "ocidex_"))
	}
}

func TestWhoamiReportsIdentityAndServer(t *testing.T) {
	i := is.New(t)

	var called bool
	api := &client.FakeClient{
		GetCurrentUserFn: func(context.Context) (client.MeOutputBody, error) {
			called = true
			return client.MeOutputBody{
				Id:          "11111111-1111-1111-1111-111111111111",
				DisplayName: "octocat",
				Role:        "member",
			}, nil
		},
	}

	res := callTool(t, connect(t, api), "ocidex_whoami", nil)
	i.True(called)
	i.True(!res.IsError)

	text := resultText(res)
	i.True(strings.Contains(text, "octocat"))
	i.True(strings.Contains(text, "member"))
	// The server URL is not something the API returns — it comes from the
	// resolved configuration, and reporting it is how an agent tells two
	// catalogs apart.
	i.True(strings.Contains(text, testServerURL))
}

// An API failure must reach the model as a readable tool error, not as a
// protocol error that the client reports as a broken server.
func TestWhoamiSurfacesAPIErrorsAsToolErrors(t *testing.T) {
	i := is.New(t)

	api := &client.FakeClient{
		GetCurrentUserFn: func(context.Context) (client.MeOutputBody, error) {
			return client.MeOutputBody{}, &client.APIError{Status: 401, Detail: "invalid api key"}
		},
	}

	res := callTool(t, connect(t, api), "ocidex_whoami", nil)
	i.True(res.IsError)

	text := resultText(res)
	i.True(strings.Contains(text, "invalid api key"))
	i.True(strings.Contains(text, "ocidex-cli login")) // the actionable half
}
