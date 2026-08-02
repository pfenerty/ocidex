// Command ocidex-cli is a command-line client for the OCIDex API.
//
// This is the minimal slice: a root command and `sbom push`, enough for CI to
// upload an SBOM for a build artifact. The full subcommand surface — output
// formatting, config files, the rest of the API — is epic ocidex-e3g and is
// deliberately not pre-empted here.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		// cobra has already printed usage for flag/arg errors; everything else
		// needs printing here. Either way the exit code is what CI reads.
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// serverConfig is the connection detail every subcommand needs.
type serverConfig struct {
	baseURL string
}

// apiKey reads the API key from the environment.
//
// It is env-only on purpose: a --api-key flag would put the credential in the
// process table and in CI logs that echo their commands.
func apiKey() (string, error) {
	key := os.Getenv("OCIDEX_API_KEY")
	if key == "" {
		return "", errors.New("OCIDEX_API_KEY is not set")
	}
	return key, nil
}

func newRootCmd() *cobra.Command {
	cfg := &serverConfig{}

	cmd := &cobra.Command{
		Use:   "ocidex-cli",
		Short: "Command-line client for OCIDex",
		// Errors returned by RunE are reported by main; cobra printing them a
		// second time, with usage attached, buries the actual message.
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	defaultURL := os.Getenv("OCIDEX_URL")
	if defaultURL == "" {
		defaultURL = "http://localhost:8080"
	}
	cmd.PersistentFlags().StringVar(&cfg.baseURL, "server", defaultURL,
		"OCIDex base URL (env OCIDEX_URL)")

	cmd.AddCommand(newSBOMCmd(cfg))
	return cmd
}
