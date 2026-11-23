package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/pkg/client"
)

const secretKey = "ocidex_SECRET_agent_key"

// agentFake knows two namespaces and records the keys it was asked to create.
func agentFake(created *[]client.CreateAPIKeyInputBody) *client.FakeClient {
	return &client.FakeClient{
		ListNamespacesFn: func(context.Context) ([]client.NamespaceResponse, error) {
			return []client.NamespaceResponse{{Id: "ns-1", Name: "acme"}, {Id: "ns-2", Name: "lab"}}, nil
		},
		CreateAPIKeyFn: func(_ context.Context, b client.CreateAPIKeyInputBody) (client.CreateAPIKeyOutputBody, error) {
			*created = append(*created, b)
			return client.CreateAPIKeyOutputBody{Key: secretKey}, nil
		},
	}
}

func TestAgentCreate(t *testing.T) {
	is := is.New(t)
	var created []client.CreateAPIKeyInputBody
	stdout, _, err := runCLI(t, agentFake(&created), "agent", "create", "--name", "bot", "--preset", "coverage", "--namespace", "lab", "--label", "laptop")
	is.NoErr(err)
	is.Equal(strings.TrimSpace(stdout), secretKey)
	is.Equal(len(created), 1)
	b := created[0]
	is.Equal(string(*b.Kind), "agent")
	is.Equal(string(*b.Preset), "coverage")
	is.Equal(*b.Namespaces, []string{"ns-2"})
	is.Equal(*b.AgentLabel, "laptop")
	is.True(b.ExpiresAt != nil)
}

func TestAgentCreateRefusesBadInput(t *testing.T) {
	is := is.New(t)
	var created []client.CreateAPIKeyInputBody
	for _, args := range [][]string{
		{"agent", "create", "--name", "x", "--namespace", "acme", "--preset", "admin"},
		{"agent", "create", "--name", "x", "--namespace", "nope"},
		{"agent", "create", "--name", "x"}, // two namespaces: must choose
		{"agent", "create", "--name", "x", "--namespace", "acme", "--expires-in", "2400h"},
	} {
		_, _, err := runCLI(t, agentFake(&created), args...)
		is.True(err != nil)
	}
	is.Equal(len(created), 0)
}

func TestApprovalList(t *testing.T) {
	is := is.New(t)
	label := "laptop"
	fake := &client.FakeClient{ListApprovalsFn: func(_ context.Context, status string) ([]client.PendingActionView, error) {
		is.Equal(status, "pending")
		return []client.PendingActionView{{Id: uuid.New(), Status: "pending", AgentLabel: &label, Effect: "Scan registry quay.io"}}, nil
	}}
	stdout, _, err := runCLI(t, fake, "approval", "list")
	is.NoErr(err)
	is.True(strings.Contains(stdout, "Scan registry quay.io"))
	is.True(strings.Contains(stdout, "laptop"))
}

func TestApprovalOpen(t *testing.T) {
	is := is.New(t)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OCIDEX_API_KEY", "ocidex_test")
	cmd, cfg := newRootCmd()
	cfg.newClient = func(client.Config) client.Client { return &client.FakeClient{} }
	var opened string
	cfg.openURL = func(u string) error { opened = u; return nil }
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--server", "https://ocidex.example/", "approval", "open", "abc"})
	is.NoErr(cmd.ExecuteContext(context.Background()))
	is.Equal(opened, "https://ocidex.example/approvals/abc")
	is.Equal(strings.TrimSpace(out.String()), opened)
}

// mcp install writes the key into the client's config, keeps what else is
// there, never prints the key, and is a no-op the second time.
func TestMCPInstall(t *testing.T) {
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "claude.json")
	is.NoErr(os.WriteFile(path, []byte(`{"theme":"dark","mcpServers":{"other":{"command":"x"}}}`), 0o644))
	var created []client.CreateAPIKeyInputBody
	fake := agentFake(&created)

	stdout, stderr, err := runCLI(t, fake, "--server", "https://ocidex.example", "mcp", "install", "--config", path, "--namespace", "acme")
	is.NoErr(err)
	is.True(!strings.Contains(stdout+stderr, secretKey))
	is.Equal(len(created), 1)
	is.Equal(string(*created[0].Preset), "analyst")
	is.Equal(created[0].Name, "mcp: claude-code")

	var doc struct {
		Theme      string `json:"theme"`
		MCPServers map[string]struct {
			Type    string            `json:"type"`
			Command string            `json:"command"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	b, err := os.ReadFile(path)
	is.NoErr(err)
	is.NoErr(json.Unmarshal(b, &doc))
	is.Equal(doc.Theme, "dark")
	is.Equal(doc.MCPServers["other"].Command, "x")
	o := doc.MCPServers["ocidex"]
	is.Equal(o.Type, "stdio")
	is.True(strings.HasSuffix(o.Command, "ocidex-mcp"))
	is.Equal(o.Env["OCIDEX_URL"], "https://ocidex.example")
	is.Equal(o.Env["OCIDEX_API_KEY"], secretKey)
	info, err := os.Stat(path)
	is.NoErr(err)
	is.Equal(info.Mode().Perm(), os.FileMode(0o600))

	// Again: nothing created, nothing changed.
	_, _, err = runCLI(t, fake, "--server", "https://ocidex.example", "mcp", "install", "--config", path, "--namespace", "acme")
	is.NoErr(err)
	is.Equal(len(created), 1)
	b2, _ := os.ReadFile(path)
	is.Equal(string(b2), string(b))

	// --rotate replaces the key.
	_, _, err = runCLI(t, fake, "--server", "https://ocidex.example", "mcp", "install", "--config", path, "--namespace", "acme", "--rotate")
	is.NoErr(err)
	is.Equal(len(created), 2)
}

func TestMCPInstallRefusesNonObjectConfig(t *testing.T) {
	is := is.New(t)
	path := filepath.Join(t.TempDir(), "mcp.json")
	is.NoErr(os.WriteFile(path, []byte(`[1,2]`), 0o600))
	var created []client.CreateAPIKeyInputBody
	_, _, err := runCLI(t, agentFake(&created), "mcp", "install", "--client", "cursor", "--config", path, "--namespace", "acme")
	is.True(err != nil)
	is.Equal(len(created), 0)
}
