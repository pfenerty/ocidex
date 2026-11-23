package main

import (
	"context"
	"os/exec"
	"runtime"
)

// openInBrowser asks the desktop to open u. It does not wait for the browser.
func openInBrowser(u string) error {
	ctx := context.Background() // the browser outlives this command
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", u)
	case "windows":
		cmd = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.CommandContext(ctx, "xdg-open", u)
	}
	return cmd.Start()
}
