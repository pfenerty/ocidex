package main

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

// configFile is the on-disk shape of ~/.config/ocidex/config.yaml.
//
// The tags are json, not yaml: sigs.k8s.io/yaml round-trips through JSON, which
// keeps the key names here consistent with how the API's own types render under
// `--output yaml`.
type configFile struct {
	Server string `json:"server,omitempty"`
	APIKey string `json:"api-key,omitempty"`
	Output string `json:"output,omitempty"`
}

// configPath is the single supported location, honouring XDG_CONFIG_HOME.
//
// There is deliberately no --config flag and no search up the directory tree: a
// per-directory config file that silently changes which server `delete` talks
// to is a footgun. It returns "" when the home directory cannot be determined,
// which callers treat as "no config file".
func configPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "ocidex", "config.yaml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "ocidex", "config.yaml")
}

// saveConfigFile writes the config file, creating its directory if needed.
//
// Mode 0600 unconditionally, not just when a key is present: loadConfigFile
// refuses a group- or world-readable file that holds a key, so writing one any
// other way would produce a config this same binary then rejects.
func saveConfigFile(cfg configFile) error {
	path := configPath()
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

// loadConfigFile reads the config file if there is one. An absent file is not
// an error — every key it can hold has an environment variable or a default.
func loadConfigFile() (configFile, error) {
	path := configPath()
	if path == "" {
		return configFile{}, nil
	}

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return configFile{}, nil
	}
	if err != nil {
		return configFile{}, fmt.Errorf("reading %s: %w", path, err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // fixed, user-owned path
	if err != nil {
		return configFile{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return configFile{}, fmt.Errorf("parsing %s: %w", path, err)
	}

	// A credential readable by the rest of the machine is refused rather than
	// used, the way ssh refuses a world-readable private key. Only the key is
	// sensitive, so a permissive file without one is fine.
	if cfg.APIKey != "" && info.Mode().Perm()&0o077 != 0 {
		return configFile{}, fmt.Errorf(
			"%s holds an api-key but is mode %04o; chmod 600 it or remove the key",
			path, info.Mode().Perm())
	}

	return cfg, nil
}
