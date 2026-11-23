package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// clientClaudeCode is the default client, and the one whose entries name
// their transport.
const clientClaudeCode = "claude-code"

// mcpServerName is the entry ocidex-mcp is registered under in a client's config.
const mcpServerName = "ocidex"

var mcpClients = []string{clientClaudeCode, "claude-desktop", "cursor"}

// mcpConfigPath is where a client keeps its MCP servers, user-wide. Each is a
// JSON file with an "mcpServers" object.
func mcpConfigPath(clientName, home string) (string, error) {
	switch clientName {
	case clientClaudeCode:
		return filepath.Join(home, ".claude.json"), nil
	case "claude-desktop":
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		}
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	}
	return "", usagef("--client must be one of %s (got %q)", strings.Join(mcpClients, ", "), clientName)
}

func newMCPCmd(cfg *rootConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Connect MCP clients to OCIDex",
	}
	cmd.AddCommand(newMCPInstallCmd(cfg))
	return cmd
}

func newMCPInstallCmd(cfg *rootConfig) *cobra.Command {
	var spec agentKeySpec
	var clientName, configPath string
	var rotate bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Register ocidex-mcp with an MCP client, using a new agent key",
		Long: `Register ocidex-mcp with an MCP client (Claude Code, Claude Desktop or Cursor).

This creates an agent key for the client (see ` + "`ocidex-cli agent create`" + `) and
writes it into the client's user-wide MCP configuration, so the client never runs
with your personal login key. The key is written only to that file, which is
kept readable by you alone; it is never printed.

Running it again changes nothing while OCIDex is already registered for this
server. --rotate creates a fresh key and replaces the old one in the file;
revoke the old key afterwards under Admin → Agents.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			configPath, err := resolveMCPConfig(clientName, configPath)
			if err != nil {
				return err
			}
			doc, err := readJSONObject(configPath)
			if err != nil {
				return err
			}
			servers, _ := doc["mcpServers"].(map[string]any)
			if servers == nil {
				servers = map[string]any{}
			}
			if existing, ok := servers[mcpServerName].(map[string]any); ok && !rotate && sameServer(existing, cfg.server) {
				fmt.Fprintf(cmd.ErrOrStderr(), "OCIDex is already registered in %s; nothing to do (--rotate replaces its key)\n", configPath)
				return nil
			}

			api, err := cfg.authed()
			if err != nil {
				return err
			}
			if spec.name == "" {
				spec.name = "mcp: " + clientName
			}
			if spec.label == "" {
				spec.label = clientName
			}
			key, err := spec.create(cmd.Context(), api)
			if err != nil {
				return err
			}
			entry := map[string]any{
				"command": mcpCommandPath(),
				"args":    []any{},
				"env":     map[string]any{"OCIDEX_URL": cfg.server, "OCIDEX_API_KEY": key},
			}
			if clientName == clientClaudeCode {
				entry["type"] = "stdio"
			}
			servers[mcpServerName] = entry
			doc["mcpServers"] = servers
			if err := writeJSONObject(configPath, doc); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "registered ocidex-mcp in %s with a new %s agent key; restart the client to pick it up\n", configPath, spec.preset)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&clientName, "client", clientClaudeCode, "the MCP client: "+strings.Join(mcpClients, ", "))
	f.StringVar(&configPath, "config", "", "the client's config file (default: the client's user-wide file)")
	f.BoolVar(&rotate, "rotate", false, "create a new key even if OCIDex is already registered")
	f.StringVar(&spec.name, "name", "", "the key's name (default \"mcp: <client>\")")
	spec.flags(cmd)
	return cmd
}

// resolveMCPConfig is the config file to edit: the one given, or the
// client's own.
func resolveMCPConfig(clientName, given string) (string, error) {
	if !slices.Contains(mcpClients, clientName) {
		return "", usagef("--client must be one of %s (got %q)", strings.Join(mcpClients, ", "), clientName)
	}
	if given != "" {
		return given, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding your home directory: %w", err)
	}
	return mcpConfigPath(clientName, home)
}

// sameServer reports whether an existing entry already points at server with a key.
func sameServer(entry map[string]any, server string) bool {
	env, _ := entry["env"].(map[string]any)
	url, _ := env["OCIDEX_URL"].(string)
	key, _ := env["OCIDEX_API_KEY"].(string)
	return key != "" && strings.TrimRight(url, "/") == strings.TrimRight(server, "/")
}

// mcpCommandPath is ocidex-mcp's absolute path when it is on PATH: desktop
// clients start servers with a minimal PATH that often misses it.
func mcpCommandPath() string {
	if p, err := exec.LookPath("ocidex-mcp"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	return "ocidex-mcp"
}

func readJSONObject(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	doc := map[string]any{}
	if len(strings.TrimSpace(string(b))) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object; fix or move it first: %w", path, err)
	}
	return doc, nil
}

// writeJSONObject replaces path atomically, readable by its owner only: it
// holds a key.
func writeJSONObject(path string, doc map[string]any) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ocidex-mcp-*.json")
	if err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
