package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/matryer/is"
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/cmd/ocidex-cli/output"
	"github.com/pfenerty/ocidex/pkg/client"
)

// resolveWith runs the root command's configuration resolution with the given
// command line, against a config directory holding contents (empty for none),
// and returns the resolved configuration.
func resolveWith(t *testing.T, contents string, mode os.FileMode, args ...string) (*rootConfig, error) {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	if contents != "" {
		if err := os.MkdirAll(filepath.Join(dir, "ocidex"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ocidex", "config.yaml"), []byte(contents), mode); err != nil {
			t.Fatal(err)
		}
	}

	root, cfg := newRootCmd()
	// A leaf command that does nothing: resolution happens in the root's
	// PersistentPreRunE, which only runs when a subcommand executes.
	root.AddCommand(&cobra.Command{
		Use:  "noop",
		RunE: func(*cobra.Command, []string) error { return nil },
	})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs(append([]string{"noop"}, args...))
	return cfg, root.ExecuteContext(context.Background())
}

func TestResolveServerPrecedence(t *testing.T) {
	const fileServer = "https://from-file.example.com"
	cfgFile := fmt.Sprintf("server: %s\n", fileServer)

	tests := []struct {
		name string
		env  string
		file string
		args []string
		want string
	}{
		{name: "default", want: defaultServer},
		{name: "config file", file: cfgFile, want: fileServer},
		{name: "env beats file", env: "https://from-env.example.com", file: cfgFile, want: "https://from-env.example.com"},
		{
			name: "flag beats env",
			env:  "https://from-env.example.com",
			file: cfgFile,
			args: []string{"--server", "https://from-flag.example.com"},
			want: "https://from-flag.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			t.Setenv("OCIDEX_URL", tt.env)
			cfg, err := resolveWith(t, tt.file, 0o600, tt.args...)
			is.NoErr(err)
			is.Equal(cfg.server, tt.want)
		})
	}
}

// TestResolveAPIKey covers the one precedence rule with no flag in it: a key in
// argv would be visible in the process table and in CI logs.
func TestResolveAPIKey(t *testing.T) {
	t.Run("env beats file", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("OCIDEX_API_KEY", "from-env")
		cfg, err := resolveWith(t, "api-key: from-file\n", 0o600)
		is.NoErr(err)
		is.Equal(cfg.apiKey, "from-env")
	})

	t.Run("file when env is unset", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("OCIDEX_API_KEY", "")
		cfg, err := resolveWith(t, "api-key: from-file\n", 0o600)
		is.NoErr(err)
		is.Equal(cfg.apiKey, "from-file")
	})

	t.Run("no flag exists", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("OCIDEX_API_KEY", "")
		_, err := resolveWith(t, "", 0o600, "--api-key", "leaked")
		is.True(err != nil)
	})

	t.Run("authed reports both sources", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("OCIDEX_API_KEY", "")
		cfg, err := resolveWith(t, "", 0o600)
		is.NoErr(err)
		_, err = cfg.authed()
		is.True(err != nil)
	})
}

func TestResolveOutput(t *testing.T) {
	tests := []struct {
		name string
		file string
		args []string
		want output.Format
		bad  bool
	}{
		{name: "default", want: output.Table},
		{name: "config file", file: "output: json\n", want: output.JSON},
		{name: "flag beats file", file: "output: json\n", args: []string{"-o", "yaml"}, want: output.YAML},
		{name: "unknown format", args: []string{"--output", "xml"}, bad: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			cfg, err := resolveWith(t, tt.file, 0o600, tt.args...)
			if tt.bad {
				is.True(err != nil)
				is.Equal(exitCode(err, cfg.resolved), exitUsage)
				return
			}
			is.NoErr(err)
			is.Equal(cfg.format, tt.want)
		})
	}
}

// TestConfigFilePermissions asserts a credential the rest of the machine can
// read is refused rather than used.
func TestConfigFilePermissions(t *testing.T) {
	t.Run("world-readable with a key is refused", func(t *testing.T) {
		is := is.New(t)
		t.Setenv("OCIDEX_API_KEY", "")
		_, err := resolveWith(t, "api-key: secret\n", 0o644)
		is.True(err != nil)
	})

	t.Run("world-readable without a key is fine", func(t *testing.T) {
		is := is.New(t)
		cfg, err := resolveWith(t, "server: https://ok.example.com\n", 0o644)
		is.NoErr(err)
		is.Equal(cfg.server, "https://ok.example.com")
	})
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		resolved bool
		want     int
	}{
		{name: "success", err: nil, resolved: true, want: exitOK},
		{name: "usage error", err: usagef("bad flag"), resolved: true, want: exitUsage},
		{name: "unresolved is a usage error", err: errors.New("unknown command"), want: exitUsage},
		{name: "not found", err: fmt.Errorf("get: %w", client.ErrNotFound), resolved: true, want: exitNotFound},
		{name: "forbidden", err: fmt.Errorf("get: %w", client.ErrForbidden), resolved: true, want: exitForbidden},
		{name: "anything else", err: errors.New("connection refused"), resolved: true, want: exitFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(exitCode(tt.err, tt.resolved), tt.want)
		})
	}
}
