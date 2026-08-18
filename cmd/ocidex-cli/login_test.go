package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matryer/is"
	"sigs.k8s.io/yaml"

	"github.com/pfenerty/ocidex/internal/cliconfig"
	"github.com/pfenerty/ocidex/pkg/client"
)

// runAuthCLI is runCLI with two differences login and logout need: stdin can be
// scripted, and OCIDEX_API_KEY is cleared so the file is the only credential
// source — with it set, logout would have nothing observable to do.
func runAuthCLI(t *testing.T, fake *client.FakeClient, home, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", home)
	t.Setenv("OCIDEX_API_KEY", "")

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	cmd, cfg := newRootCmd()
	cfg.newClient = func(client.Config) client.Client { return fake }
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err = cmd.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func writeConfig(t *testing.T, home string, cfg cliconfig.File) string {
	t.Helper()
	path := filepath.Join(home, "ocidex", "config.yaml")
	is.New(t).NoErr(os.MkdirAll(filepath.Dir(path), 0o700))
	data, err := yaml.Marshal(cfg)
	is.New(t).NoErr(err)
	is.New(t).NoErr(os.WriteFile(path, data, 0o600))
	return path
}

func readConfig(t *testing.T, home string) cliconfig.File {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, "ocidex", "config.yaml"))
	is.New(t).NoErr(err)
	var cfg cliconfig.File
	is.New(t).NoErr(yaml.Unmarshal(data, &cfg))
	return cfg
}

func fakeUser() *client.FakeClient {
	return &client.FakeClient{
		GetCurrentUserFn: func(context.Context) (client.MeOutputBody, error) {
			return client.MeOutputBody{Id: "u1", GithubUsername: "pfenerty", Role: "admin"}, nil
		},
	}
}

func TestLogin(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()

	stdout, stderr, err := runAuthCLI(t, fakeUser(), home, "",
		"login", "--server-url", "https://ocidex.app", "--key", "ocidex_abc")
	is.NoErr(err)

	got := readConfig(t, home)
	is.Equal(got.Server, "https://ocidex.app")
	is.Equal(got.APIKey, "ocidex_abc")

	// A credential file the rest of the machine can read is one loadConfigFile
	// will refuse on the next command, so the mode is part of the contract.
	info, err := os.Stat(filepath.Join(home, "ocidex", "config.yaml"))
	is.NoErr(err)
	is.Equal(info.Mode().Perm(), os.FileMode(0o600))

	is.Equal(stdout, "")
	is.True(strings.Contains(stderr, "pfenerty"))
}

func TestLoginPrompts(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()

	_, stderr, err := runAuthCLI(t, fakeUser(), home, "https://prompted.example\nocidex_typed\n", "login")
	is.NoErr(err)

	got := readConfig(t, home)
	is.Equal(got.Server, "https://prompted.example")
	is.Equal(got.APIKey, "ocidex_typed")
	// Prompts go to stderr so they never land in piped output.
	is.True(strings.Contains(stderr, "Server URL"))
	is.True(strings.Contains(stderr, "API key"))
}

// An empty answer at the server prompt keeps the already-resolved server rather
// than writing "".
func TestLoginServerDefault(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()
	writeConfig(t, home, cliconfig.File{Server: "https://existing.example"})

	_, _, err := runAuthCLI(t, fakeUser(), home, "\nocidex_typed\n", "login")
	is.NoErr(err)
	is.Equal(readConfig(t, home).Server, "https://existing.example")
}

// A key that does not work must not be written: persisting it would move the
// failure to the next command, where it is harder to explain.
func TestLoginRejectsBadKey(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()
	fake := &client.FakeClient{
		GetCurrentUserFn: func(context.Context) (client.MeOutputBody, error) {
			return client.MeOutputBody{}, errors.New("401 unauthorized")
		},
	}

	_, _, err := runAuthCLI(t, fake, home, "", "login", "--key", "bad")
	is.True(err != nil)

	_, statErr := os.Stat(filepath.Join(home, "ocidex", "config.yaml"))
	is.True(os.IsNotExist(statErr))
}

func TestLoginRequiresKey(t *testing.T) {
	is := is.New(t)
	// Empty answers to both prompts: there is no default for a credential.
	_, _, err := runAuthCLI(t, fakeUser(), t.TempDir(), "\n\n", "login")
	is.True(err != nil)
}

func TestLogout(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()
	writeConfig(t, home, cliconfig.File{Server: "https://ocidex.app", APIKey: "ocidex_abc", Output: "json"})

	_, stderr, err := runAuthCLI(t, &client.FakeClient{}, home, "", "logout")
	is.NoErr(err)

	// Settings survive; only the credential goes. Re-typing a server URL after
	// every logout is friction with no security benefit.
	got := readConfig(t, home)
	is.Equal(got.APIKey, "")
	is.Equal(got.Server, "https://ocidex.app")
	is.Equal(got.Output, "json")
	is.True(strings.Contains(stderr, "removed"))
}

// Nothing but the key was in the file, so nothing should be left behind.
func TestLogoutRemovesEmptyFile(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()
	path := writeConfig(t, home, cliconfig.File{APIKey: "ocidex_abc"})

	_, _, err := runAuthCLI(t, &client.FakeClient{}, home, "", "logout")
	is.NoErr(err)

	_, statErr := os.Stat(path)
	is.True(os.IsNotExist(statErr))
}

func TestLogoutWithoutKey(t *testing.T) {
	is := is.New(t)
	_, stderr, err := runAuthCLI(t, &client.FakeClient{}, t.TempDir(), "", "logout")
	is.NoErr(err)
	is.True(strings.Contains(stderr, "no stored API key"))
}

// OCIDEX_API_KEY outranks the file, so a logout that leaves it set has not
// actually logged anyone out and must say so.
func TestLogoutWarnsAboutEnv(t *testing.T) {
	is := is.New(t)
	home := t.TempDir()
	writeConfig(t, home, cliconfig.File{APIKey: "ocidex_abc"})
	t.Setenv("OCIDEX_API_KEY", "ocidex_env")

	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	t.Setenv("XDG_CONFIG_HOME", home)
	cmd, cfg := newRootCmd()
	cfg.newClient = func(client.Config) client.Client { return &client.FakeClient{} }
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs([]string{"logout"})
	is.NoErr(cmd.ExecuteContext(context.Background()))
	is.True(strings.Contains(errOut.String(), "OCIDEX_API_KEY is still set"))
}
