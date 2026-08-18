// Command ocidex-mcp exposes the OCIDex catalog to agents as a Model Context
// Protocol server over stdio.
//
// The design — why a standalone binary over the generated pkg/client SDK rather
// than an endpoint on the API, and why credentials come from `ocidex-cli login`
// — is recorded in docs/adr/0045-mcp-server.md.
//
// Register it with an MCP client, for example:
//
//	claude mcp add ocidex -- ocidex-mcp
//
// It speaks JSON-RPC on stdin/stdout, so nothing but the protocol may be written
// to stdout: logs and startup diagnostics go to stderr, which the client shows
// as server output.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/pfenerty/ocidex/internal/cliconfig"
	"github.com/pfenerty/ocidex/internal/version"
	"github.com/pfenerty/ocidex/pkg/client"
)

// Exit codes. 2 is a configuration problem the user must fix — a missing key, an
// unreadable config file — and is worth separating from 1, a session that
// started and then failed, because only the former is actionable before the
// next launch.
const (
	exitOK     = 0
	exitError  = 1
	exitConfig = 2
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run is main's testable body: argv and the diagnostic stream are parameters,
// and it returns an exit code instead of calling os.Exit.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("ocidex-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "",
		"OCIDex base URL (env OCIDEX_URL, config server, default "+cliconfig.DefaultServer+")")
	showVersion := fs.Bool("version", false, "Print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: ocidex-mcp [flags]\n\n"+
			"Serves the OCIDex catalog to MCP clients over stdio. Credentials come from\n"+
			"`ocidex-cli login`, OCIDEX_API_KEY, or %s.\n\nFlags:\n", cliconfig.Path())
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		// ContinueOnError has already printed the message and usage.
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitConfig
	}
	if *showVersion {
		fmt.Fprintf(stderr, "ocidex-mcp %s\n", version.String())
		return exitOK
	}

	settings, err := resolveSettings(*server)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitConfig
	}

	// SIGINT/SIGTERM cancel the session so Run returns and the deferred cleanup
	// happens. An MCP client normally stops a stdio server by closing its stdin,
	// which Run already treats as end of session; signals cover the case where
	// the client is killed and the pipe outlives it.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	api := client.New(client.Config{BaseURL: settings.Server, APIKey: settings.APIKey})

	// Announced on stderr, not stdout: stdout carries the JSON-RPC framing and
	// any stray byte there desynchronises the client.
	fmt.Fprintf(stderr, "ocidex-mcp %s serving %s over stdio\n", version.String(), settings.Server)

	// IOTransport over a watched stdin rather than StdioTransport, which reads
	// os.Stdin directly: the watcher is what lets the error handling below tell
	// a client that closed the pipe from a session that broke while it was open.
	stdin := &stdinWatcher{ReadCloser: os.Stdin}
	err = newServer(api, settings.Server).Run(ctx, &mcp.IOTransport{Reader: stdin, Writer: os.Stdout})
	if err != nil {
		// Both ordinary endings: a signal cancelled the session, or the client
		// closed our stdin — which is how MCP clients stop a stdio server, and
		// which surfaces as an in-flight write failure when it happens mid
		// request. Reporting either as a failure would put a spurious error in
		// the client's server log on every clean shutdown.
		if errors.Is(err, context.Canceled) || stdin.sawEOF() {
			return exitOK
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitError
	}
	return exitOK
}

// stdinWatcher records whether the input stream reached EOF.
//
// The SDK reports a shutdown caused by the peer going away as an opaque
// "server is closing: EOF" — the EOF is formatted into the message rather than
// wrapped, so errors.Is cannot see it, and the sentinel it does wrap lives in an
// internal package. Watching the read side is the version of this check that
// does not depend on either.
type stdinWatcher struct {
	io.ReadCloser
	eof atomic.Bool
}

func (w *stdinWatcher) Read(p []byte) (int, error) {
	n, err := w.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		w.eof.Store(true)
	}
	return n, err
}

// sawEOF reports whether the client closed its end. It is read from the
// goroutine running run while the SDK's reader goroutine writes it, hence the
// atomic.
func (w *stdinWatcher) sawEOF() bool { return w.eof.Load() }

// resolveSettings reads the shared config file and applies the same precedence
// ocidex-cli uses, then insists on a key.
//
// The key is required at startup rather than at the first tool call: an MCP
// server that connects cleanly and then fails every tool looks to a model like a
// broken catalog, whereas refusing to start surfaces the real problem in the
// client's server log where a human will read it.
func resolveSettings(serverOverride string) (cliconfig.Settings, error) {
	file, err := cliconfig.Load()
	if err != nil {
		return cliconfig.Settings{}, err
	}
	settings := cliconfig.Resolve(file, serverOverride)
	if err := settings.RequireKey(); err != nil {
		return cliconfig.Settings{}, fmt.Errorf("%w; run `ocidex-cli login` first", err)
	}
	return settings, nil
}
