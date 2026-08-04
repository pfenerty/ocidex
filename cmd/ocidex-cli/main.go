// Command ocidex-cli is a command-line client for the OCIDex API.
//
// Its design — binary name, noun-verb grammar, configuration precedence, output
// formats and exit codes — is recorded in docs/adr/0029-cli-design.md.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/pfenerty/ocidex/pkg/client"
)

// Exit codes. 3 and 4 exist because "absent" and "not allowed to see" is the
// distinction a script most often branches on, and pkg/client's typed sentinels
// make it free. Anything more granular belongs in the stderr message.
const (
	exitOK        = 0
	exitFailure   = 1
	exitUsage     = 2
	exitNotFound  = 3
	exitForbidden = 4
)

func main() {
	os.Exit(run())
}

func run() int {
	root, cfg := newRootCmd()

	// ExecuteC, not Execute: on failure it returns the command that failed, so
	// usage can be printed for that command rather than for the root.
	cmd, err := root.ExecuteC()
	if err == nil {
		return exitOK
	}

	fmt.Fprintln(os.Stderr, "error:", err)

	code := exitCode(err, cfg.resolved)
	if code == exitUsage {
		fmt.Fprint(os.Stderr, cmd.UsageString())
	}
	return code
}

// exitCode classifies a failure. resolved reports whether the root command's
// PersistentPreRunE ran: cobra surfaces flag-parsing, required-flag and
// unknown-command failures the same way it surfaces a command's own error, and
// happening before resolution is what distinguishes them.
func exitCode(err error, resolved bool) int {
	var usageErr *usageError
	switch {
	case err == nil:
		return exitOK
	case errors.As(err, &usageErr), !resolved:
		return exitUsage
	case errors.Is(err, client.ErrNotFound):
		return exitNotFound
	case errors.Is(err, client.ErrForbidden):
		return exitForbidden
	default:
		return exitFailure
	}
}
