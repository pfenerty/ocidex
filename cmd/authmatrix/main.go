// Package main renders the authorization matrix to stdout. It constructs the
// router with nil services (no handlers are invoked) and joins the resulting
// OpenAPI operations against the authRules declarations in internal/api.
//
// Usage:
//
//	go run ./cmd/authmatrix > docs/AUTH_MATRIX.md
package main

import (
	"fmt"
	"os"

	"github.com/pfenerty/ocidex/internal/api"
)

func main() {
	h := api.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	_ = api.NewRouter(h, "*", "", "")

	if _, err := os.Stdout.WriteString(api.AuthMatrixMarkdown(h.API().OpenAPI())); err != nil {
		fmt.Fprintf(os.Stderr, "error writing matrix: %v\n", err)
		os.Exit(1)
	}
}
