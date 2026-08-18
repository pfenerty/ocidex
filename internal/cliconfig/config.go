// Package cliconfig holds the server URL and credential handling shared by the
// user-facing client binaries — ocidex-cli and ocidex-mcp.
//
// It lives here rather than in cmd/ocidex-cli because a second credential store
// is the failure mode worth designing against: `ocidex-cli login` must provision
// every client on the machine, so the file layout, the precedence rules and the
// permission check all have exactly one implementation.
package cliconfig

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

// DefaultServer is the last resort when no flag, environment variable, or config
// file names a server.
const DefaultServer = "http://localhost:8080"

// File is the on-disk shape of ~/.config/ocidex/config.yaml.
//
// The tags are json, not yaml: sigs.k8s.io/yaml round-trips through JSON, which
// keeps the key names here consistent with how the API's own types render under
// `--output yaml`.
type File struct {
	Server string `json:"server,omitempty"`
	APIKey string `json:"api-key,omitempty"`
	Output string `json:"output,omitempty"`
}

// Path is the single supported location, honouring XDG_CONFIG_HOME.
//
// There is deliberately no --config flag and no search up the directory tree: a
// per-directory config file that silently changes which server `delete` talks
// to is a footgun. It returns "" when the home directory cannot be determined,
// which callers treat as "no config file".
func Path() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "ocidex", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "ocidex", "config.yaml")
}

// Save writes the config file, creating its directory if needed.
//
// Mode 0600 unconditionally, not just when a key is present: Load refuses a
// group- or world-readable file that holds a key, so writing one any other way
// would produce a config this same binary then rejects.
func Save(cfg File) error {
	path := Path()
	if path == "" {
		return fmt.Errorf("cannot determine home directory; set XDG_CONFIG_HOME")
	}

	// gosec flags marshalling a struct with a credential field. Persisting
	// that credential is what this function is for; the 0600 below is the
	// mitigation.
	data, err := yaml.Marshal(cfg) //nolint:gosec // G117: writing the key is the point
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// Load reads the config file if there is one. An absent file is not an error —
// every key it can hold has an environment variable or a default.
func Load() (File, error) {
	path := Path()
	if path == "" {
		return File{}, nil
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return File{}, nil
	}
	if err != nil {
		return File{}, fmt.Errorf("reading %s: %w", path, err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // fixed, user-owned path
	if err != nil {
		return File{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg File
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return File{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	// A credential readable by the rest of the machine is refused rather than
	// used, the way ssh refuses a world-readable private key. Only the key is
	// sensitive, so a permissive file without one is fine.
	if cfg.APIKey != "" && info.Mode().Perm()&0o077 != 0 {
		return File{}, fmt.Errorf(
			"%s holds an api-key but is mode %04o; chmod 600 it or remove the key",
			path, info.Mode().Perm())
	}

	return cfg, nil
}

// Settings is the resolved server URL and credential a client binary connects
// with.
type Settings struct {
	Server string
	APIKey string
}

// Resolve applies the precedence rules to an already-loaded file: the caller's
// override (a --server flag, empty when unset), then the environment, then the
// file, then the built-in default.
//
// It takes the File rather than loading one so a caller that also needs
// File.Output does not read and permission-check the file twice.
//
// There is deliberately no override parameter for the key: a credential in argv
// is visible in the process table and echoed by any CI runner that logs its
// commands, so OCIDEX_API_KEY and the 0600 file are the only two ways in.
func Resolve(file File, serverOverride string) Settings {
	return Settings{
		Server: firstNonEmpty(serverOverride, os.Getenv("OCIDEX_URL"), file.Server, DefaultServer),
		APIKey: firstNonEmpty(os.Getenv("OCIDEX_API_KEY"), file.APIKey),
	}
}

// RequireKey reports the absence of a credential, naming both places one can
// come from. Callers that cannot work anonymously use it so every binary fails
// the same way and points at the same fix.
func (s Settings) RequireKey() error {
	if s.APIKey == "" {
		return fmt.Errorf("no API key: set OCIDEX_API_KEY or add api-key to %s", Path())
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
