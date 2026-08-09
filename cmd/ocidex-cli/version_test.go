package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// runVersion executes the given argv against a fresh root command and returns
// everything it wrote to stdout and stderr.
func runVersion(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	root, _ := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestVersionCommand(t *testing.T) {
	is := is.New(t)

	out, err := runVersion(t, "version")
	is.NoErr(err)
	is.True(strings.HasPrefix(out, "ocidex-cli "))
	is.True(strings.Contains(out, "commit "))
	is.True(strings.Contains(out, "built "))
}

// The --version flag and the subcommand are the same line: cobra answers the
// flag from its own template, and a divergence there is invisible until someone
// pastes the wrong one into a bug report.
func TestVersionFlagMatchesSubcommand(t *testing.T) {
	is := is.New(t)

	fromCmd, err := runVersion(t, "version")
	is.NoErr(err)
	fromFlag, err := runVersion(t, "--version")
	is.NoErr(err)
	is.Equal(fromFlag, fromCmd)
}

// TestVersionIgnoresBrokenConfig is the reason the version command shadows the
// root's PersistentPreRunE: a config file this same binary refuses to read is
// exactly the state someone runs `version` to help diagnose.
func TestVersionIgnoresBrokenConfig(t *testing.T) {
	is := is.New(t)

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	is.NoErr(os.MkdirAll(filepath.Join(dir, "ocidex"), 0o700))
	// World-readable and holding a key: loadConfigFile refuses this outright.
	is.NoErr(os.WriteFile(filepath.Join(dir, "ocidex", "config.yaml"), []byte("api-key: secret\n"), 0o644))

	out, err := runVersion(t, "version")
	is.NoErr(err)
	is.True(strings.HasPrefix(out, "ocidex-cli "))
}
