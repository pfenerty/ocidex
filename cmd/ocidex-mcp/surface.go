package main

import (
	"context"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/pkg/client"
)

// keySurface is what the configured key may do, read from the server at
// startup (ADR-0058 A8). Write tools are registered only when it allows them,
// so a model never sees a tool its key cannot use.
type keySurface struct {
	kind             string
	capabilities     []string
	approvalRequired []string
	namespaces       []string
	expiresAt        *time.Time
}

// personalKeyHint is what an agent is told when write tools are off.
const personalKeyHint = "This server is read-only because its key is not an agent key. " +
	"Run `ocidex-cli mcp install` to give it an agent key, limited to chosen namespaces and expiring."

// surfaceTimeout bounds the startup lookup. A slow server leaves the tools
// read-only rather than stalling the client's handshake.
const surfaceTimeout = 5 * time.Second

// loadSurface reads the key's surface. Any failure, including an older server
// without the endpoint, yields the read-only surface.
func loadSurface(api client.Client) keySurface {
	ctx, cancel := context.WithTimeout(context.Background(), surfaceTimeout)
	defer cancel()
	s, _ := fetchSurface(ctx, api)
	return s
}

func fetchSurface(ctx context.Context, api client.Client) (keySurface, bool) {
	self, err := api.GetKeySelf(ctx)
	if err != nil {
		return keySurface{}, false
	}
	s := keySurface{kind: string(self.Kind), expiresAt: self.ExpiresAt}
	if self.Capabilities != nil {
		s.capabilities = *self.Capabilities
	}
	if self.ApprovalRequired != nil {
		s.approvalRequired = *self.ApprovalRequired
	}
	if self.Namespaces != nil {
		s.namespaces = *self.Namespaces
	}
	return s, true
}

// writes reports whether this server offers write tools at all: only an agent
// key, which is limited, time-boxed and attributable, gets them.
func (s keySurface) writes() bool { return s.kind == "agent" }

// allows reports whether a write tool needing capability may be offered. An
// empty capability is a write that needs none (the holder's own watchlist).
func (s keySurface) allows(capability string) bool {
	if !s.writes() {
		return false
	}
	return capability == "" || slices.Contains(s.capabilities, capability)
}

// held reports whether a write needing capability will be held for approval.
func (s keySurface) held(capability string) bool {
	return slices.Contains(s.approvalRequired, capability)
}

// registerWriteTools registers the write tools the key allows. The tools
// themselves land with ocidex-m3yx.8; this is the gate they register through.
func registerWriteTools(_ *mcp.Server, _ client.Client, _ keySurface) {}
