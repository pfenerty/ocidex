package main

import (
	"strings"

	"github.com/pfenerty/ocidex/internal/api"
)

// authorizationPage is the authorization matrix docs/AUTH_MATRIX.md also
// carries, re-headed for the site: its H1 and generator comment are dropped and
// its repo-relative links point at GitHub.
func authorizationPage() string {
	h := api.NewHandler(api.Deps{})
	_ = api.NewRouter(h, "*", "", "")
	md := api.AuthMatrixMarkdown(h.API().OpenAPI())

	var kept []string
	for _, line := range strings.Split(md, "\n") {
		if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "<!-- Generated") {
			continue
		}
		kept = append(kept, line)
	}
	body := strings.TrimLeft(strings.Join(kept, "\n"), "\n")
	body = strings.ReplaceAll(body, "](../", "]("+githubBlob)
	body = strings.ReplaceAll(body, "](adr/", "]("+githubBlob+"docs/adr/")
	return frontmatter("Authorization matrix",
		"Who may call each API operation: its auth class and the capability it needs.", 5) + body
}
