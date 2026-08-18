package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/internal/version"
	"github.com/pfenerty/ocidex/pkg/client"
)

// serverName is the identity reported in the MCP initialize handshake. It is
// also the name to register the binary under (`claude mcp add ocidex ...`),
// which keeps tool names and server name consistent in a client's UI.
const serverName = "ocidex"

// instructions is sent to the client at initialize and is the only place to
// teach a model how this catalog is shaped before it picks a tool. It is
// deliberately about *choosing between* tools; per-tool detail belongs in each
// tool's own description, which the model sees alongside the schema.
const instructions = `OCIDex catalogs software artifacts and their SBOMs: which components and
licenses an artifact contains, how those change between versions, and which
vulnerabilities affect them.

Prefer the name-keyed lookup tools over UUID ones — you will usually have an
image name, not an id. When a lookup reports several candidates, retry with one
more qualifier from the list it returns rather than guessing.

Results are limited to namespaces the configured API key can see; an empty
result means "nothing visible", not necessarily "nothing exists".`

// newServer builds the MCP server over an OCIDex API client.
//
// It takes the client.Client interface rather than a Config so tests can pass
// pkg/client's FakeClient and exercise every tool without a server; that
// substitution is the whole reason the interface exists. server is the base URL
// the client was built from, carried separately because Client deliberately does
// not expose it — tools report it so an agent can tell which catalog answered.
func newServer(api client.Client, server string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
		Title:   "OCIDex software catalog",
	}, &mcp.ServerOptions{
		Instructions: instructions,
	})

	registerIdentityTools(srv, api, server)
	registerCatalogTools(srv, api)
	return srv
}

// whoamiInput is empty: the tool takes the identity of the configured key, and
// an argument that could name a *different* user would be a lie — the server
// authenticates the key, not the request.
type whoamiInput struct{}

// whoamiOutput is what an agent needs to decide whether a write will be allowed
// before attempting it.
type whoamiOutput struct {
	UserID   string `json:"user_id" jsonschema:"UUID of the authenticated user"`
	Username string `json:"username" jsonschema:"GitHub login of the authenticated user"`
	Role     string `json:"role" jsonschema:"Role of the authenticated user: admin, member, or viewer"`
	Server   string `json:"server" jsonschema:"Base URL of the OCIDex server these tools talk to"`
}

// registerIdentityTools adds the tools that describe the session itself.
//
// whoami doubles as the connectivity check: it is the cheapest authenticated
// call in the API, so an agent that cannot tell a bad key from an unreachable
// server can ask once and get a mapped error either way.
func registerIdentityTools(srv *mcp.Server, api client.Client, server string) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "ocidex_whoami",
		Description: "Report which OCIDex server these tools are talking to and which user the " +
			"configured API key belongs to. Use it to confirm connectivity and to check the " +
			"role before attempting a write.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ whoamiInput) (*mcp.CallToolResult, whoamiOutput, error) {
		me, err := api.GetCurrentUser(ctx)
		if err != nil {
			return nil, whoamiOutput{}, toolError("identifying the configured API key", err)
		}
		return nil, whoamiOutput{
			UserID:   me.Id,
			Username: me.GithubUsername,
			Role:     me.Role,
			Server:   server,
		}, nil
	})
}
