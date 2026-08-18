package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
	"sigs.k8s.io/yaml"

	"github.com/pfenerty/ocidex/internal/cliconfig"
)

// isolateConfig points the shared config loader at a temporary home and clears
// the environment override, so a real ~/.config/ocidex/config.yaml on the
// machine running the tests cannot make them pass.
func isolateConfig(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("OCIDEX_API_KEY", "")
	t.Setenv("OCIDEX_URL", "")
	return home
}

func writeConfig(t *testing.T, home string, cfg cliconfig.File) {
	t.Helper()
	dir := filepath.Join(home, "ocidex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunVersion(t *testing.T) {
	i := is.New(t)
	isolateConfig(t)

	var errOut bytes.Buffer
	i.Equal(run(context.Background(), []string{"--version"}, &errOut), exitOK)
	i.True(strings.HasPrefix(errOut.String(), "ocidex-mcp "))
}

// Refusing to start without a key is deliberate: a server that connects and
// then fails every tool reads to a model as an empty catalog.
func TestRunWithoutCredentialsFailsAtStartup(t *testing.T) {
	i := is.New(t)
	isolateConfig(t)

	var errOut bytes.Buffer
	i.Equal(run(context.Background(), nil, &errOut), exitConfig)
	i.True(strings.Contains(errOut.String(), "no API key"))
	i.True(strings.Contains(errOut.String(), "ocidex-cli login"))
}

func TestRunRejectsUnknownFlags(t *testing.T) {
	i := is.New(t)
	isolateConfig(t)

	var errOut bytes.Buffer
	i.Equal(run(context.Background(), []string{"--nope"}, &errOut), exitConfig)
}

// The whole point of sharing internal/cliconfig: a key written by
// `ocidex-cli login` provisions this binary too, with no second store.
func TestResolveSettingsReadsCLICredentials(t *testing.T) {
	i := is.New(t)
	home := isolateConfig(t)
	writeConfig(t, home, cliconfig.File{Server: "https://ocidex.example", APIKey: "ocidex_from_file"})

	settings, err := resolveSettings("")
	i.NoErr(err)
	i.Equal(settings.Server, "https://ocidex.example")
	i.Equal(settings.APIKey, "ocidex_from_file")
}

func TestResolveSettingsPrecedence(t *testing.T) {
	home := isolateConfig(t)
	writeConfig(t, home, cliconfig.File{Server: "https://from-file.example", APIKey: "ocidex_from_file"})

	t.Run("flag beats file", func(t *testing.T) {
		i := is.New(t)
		settings, err := resolveSettings("https://from-flag.example")
		i.NoErr(err)
		i.Equal(settings.Server, "https://from-flag.example")
	})

	t.Run("env beats file", func(t *testing.T) {
		i := is.New(t)
		t.Setenv("OCIDEX_URL", "https://from-env.example")
		t.Setenv("OCIDEX_API_KEY", "ocidex_from_env")

		settings, err := resolveSettings("")
		i.NoErr(err)
		i.Equal(settings.Server, "https://from-env.example")
		i.Equal(settings.APIKey, "ocidex_from_env")
	})
}

// The watcher is what distinguishes "the client went away", which is how a
// stdio server is meant to end, from a session that broke while the pipe was
// still open. Getting it backwards puts an error in the client's log on every
// clean shutdown, or hides a real failure.
func TestStdinWatcherDistinguishesEOFFromFailure(t *testing.T) {
	t.Run("EOF is recorded", func(t *testing.T) {
		i := is.New(t)
		w := &stdinWatcher{ReadCloser: io.NopCloser(strings.NewReader("hello"))}
		i.True(!w.sawEOF())

		_, err := io.ReadAll(w)
		i.NoErr(err)
		i.True(w.sawEOF())
	})

	t.Run("other read errors are not", func(t *testing.T) {
		i := is.New(t)
		w := &stdinWatcher{ReadCloser: io.NopCloser(errReader{errors.New("i/o error")})}

		_, err := io.ReadAll(w)
		i.True(err != nil)
		i.True(!w.sawEOF())
	})
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// A key readable by the rest of the machine is refused rather than used, and
// that refusal has to stop the server rather than be logged and ignored.
func TestResolveSettingsRejectsWorldReadableKey(t *testing.T) {
	i := is.New(t)
	home := isolateConfig(t)
	writeConfig(t, home, cliconfig.File{APIKey: "ocidex_abc"})
	i.NoErr(os.Chmod(filepath.Join(home, "ocidex", "config.yaml"), 0o644))

	_, err := resolveSettings("")
	i.True(err != nil)
	i.True(strings.Contains(err.Error(), "chmod 600"))
}
