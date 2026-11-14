package main

import (
	"fmt"
	"strings"

	"github.com/pfenerty/ocidex/internal/config"
)

// configurationPage lists every environment variable, grouped as EnvDocs
// groups them, with the default and required flag the env tags declare.
func configurationPage() string {
	var b strings.Builder
	b.WriteString(frontmatter("Configuration",
		"Every environment variable OCIDex reads, with its default.", 2))
	b.WriteString(`Every OCIDex process is configured with environment variables. The API, the
scanner and the enricher workers share one set; the vuln-worker, operator and k8s-agent
read their own. The Helm charts set these for you from their values (see the
[Helm values reference](/reference/helm-values/)); set them directly when you run a
binary yourself.

A variable marked **required** stops the process at startup when it is missing.
`)
	vars := config.EnvVars()
	group := ""
	for _, d := range config.EnvDocs {
		if d.Group != group {
			group = d.Group
			fmt.Fprintf(&b, "\n## %s\n\n| Variable | Default | Description |\n| --- | --- | --- |\n", group)
		}
		v := vars[d.Name]
		def := "—"
		if v.Default != "" {
			def = "`" + v.Default + "`"
		}
		desc := cell(d.Description)
		if v.Required {
			desc = "**Required.** " + desc
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", keyCell(d.Name), cell(def), desc)
	}
	return b.String()
}

// cell makes text safe for one Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// keyCell renders a variable or values key as code that may wrap after a dot or
// underscore, and nowhere else. <wbr> is not copied with the text, unlike a
// zero-width space.
func keyCell(k string) string {
	k = strings.NewReplacer(".", ".<wbr>", "_", "_<wbr>").Replace(k)
	return "<code>" + k + "</code>"
}
