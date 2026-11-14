package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// helmCharts are the charts the reference covers, in page order.
var helmCharts = []struct{ dir, blurb string }{
	{"ocidex", "The application: API, web, NATS, scanner, enrichers, vuln-worker and the migrate Job."},
	{"ocidex-operator", "The optional operator that manages registries, scans and API keys as Kubernetes resources."},
	{"ocidex-k8s-agent", "The inventory agent, installed once in each cluster OCIDex should see."},
}

// helmValuesPage renders each chart's values.yaml as a table of leaf keys,
// described by the comments above them.
func helmValuesPage(chartsDir string) (string, error) {
	var b strings.Builder
	b.WriteString(frontmatter("Helm values",
		"Every value the OCIDex Helm charts accept, with its default.", 3))
	b.WriteString(`The charts are published to ` + "`oci://ghcr.io/pfenerty/charts`" + `. This page lists every
value with its default and the comment that documents it in the chart's ` + "`values.yaml`" + `.
A value whose default is a map or list shows it inline.
`)
	for _, c := range helmCharts {
		raw, err := os.ReadFile(filepath.Join(chartsDir, c.dir, "values.yaml"))
		if err != nil {
			return "", err
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return "", fmt.Errorf("%s/values.yaml: %w", c.dir, err)
		}
		fmt.Fprintf(&b, "\n## %s\n\n%s\n\n| Key | Default | Description |\n| --- | --- | --- |\n", c.dir, c.blurb)
		if len(doc.Content) > 0 {
			walkValues(&b, doc.Content[0], "")
		}
	}
	return b.String(), nil
}

// walkValues writes one row per leaf. A non-empty map is descended into; when
// it carries a comment of its own, that comment gets a row of its own, above
// its children, rather than being repeated on each of them.
func walkValues(b *strings.Builder, n *yaml.Node, prefix string) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]
		path := key.Value
		if prefix != "" {
			path = prefix + "." + key.Value
		}
		desc := commentText(key.HeadComment, key.LineComment, val.LineComment)
		if val.Kind == yaml.MappingNode && len(val.Content) > 0 {
			if desc != "" {
				fmt.Fprintf(b, "| %s | | %s |\n", keyCell(path), cell(desc))
			}
			walkValues(b, val, path)
			continue
		}
		fmt.Fprintf(b, "| %s | %s | %s |\n", keyCell(path), cell(defaultOf(val)), cell(desc))
	}
}

// defaultOf renders a value's default compactly.
func defaultOf(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		if n.Tag == "!!null" {
			return "`null`"
		}
		if n.Value == "" {
			return `""`
		}
		return "`" + n.Value + "`"
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return ""
	}
	out, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return "`" + string(out) + "`"
}

// commentText joins comment blocks into prose. Section rules ("--- Images ---")
// and indented lines (example commands and YAML) are dropped: they read as
// noise in a table cell, and the chart's values.yaml still has them.
func commentText(blocks ...string) string {
	var words []string
	for _, block := range blocks {
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimPrefix(strings.TrimSpace(line), "#")
			if strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t") {
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "---") {
				continue
			}
			words = append(words, line)
		}
	}
	return commentProse(strings.Join(words, " "))
}

// cliFlag is a command-line flag written in a comment, like --set image.tag=X.
var cliFlag = regexp.MustCompile(`(^|\s)(--[a-z][\w.-]*(=\S+)?)`)

// commentProse makes a values.yaml comment safe as Markdown: "<tag>" would be
// read as an HTML tag and vanish, and "--set" would be typeset as an en dash.
func commentProse(s string) string {
	s = strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(s)
	return cliFlag.ReplaceAllString(s, "$1`$2`")
}
