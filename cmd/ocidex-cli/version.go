package main

import (
	"github.com/spf13/cobra"

	"github.com/pfenerty/ocidex/internal/version"
)

// newVersionCmd reports which build of the CLI this is. Since the binary is
// distributed — `go install`, or the published image — this is the only way to
// answer "what is the user actually running" (ADR-029, Distribution).
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the CLI version, commit, and build date",
		Args:  cobra.NoArgs,
		// Deliberately shadows the root's PersistentPreRunE — cobra runs only
		// the nearest one. Reporting the version must not fail because the
		// config file is unparseable or holds a world-readable api-key, which
		// is exactly the state someone runs `version` to help debug.
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println("ocidex-cli " + version.String())
			return nil
		},
	}
}
