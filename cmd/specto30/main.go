// Package main converts the OpenAPI 3.1 spec to 3.0 for oapi-codegen, which does
// not support 3.1 yet. Huma v2 emits 3.1; this rewrites the two incompatible
// patterns the spec actually uses:
//
//   - type: [array, null]  ->  type: array + nullable: true
//   - openapi: 3.1.0       ->  openapi: 3.0.3
//
// It replaces scripts/spec-to-3.0.py so codegen checks need only Go (ocidex-gyr0.5).
//
// Usage:
//
//	go run ./cmd/specto30 web/openapi.json > /tmp/openapi-3.0.json
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: specto30 <openapi-3.1.json>")
		os.Exit(2)
	}
	out, err := convert(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "specto30: %v\n", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "specto30: writing output: %v\n", err)
		os.Exit(1)
	}
}

func convert(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied path
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numeric literals exactly as written
	var spec map[string]any
	if err := dec.Decode(&spec); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	spec["openapi"] = "3.0.3"
	downconvert(spec)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(spec); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// downconvert rewrites, in place, every object whose "type" is a list.
func downconvert(v any) {
	switch v := v.(type) {
	case map[string]any:
		if types, ok := v["type"].([]any); ok {
			kept := []any{}
			nullable := false
			for _, t := range types {
				if t == "null" {
					nullable = true
				} else {
					kept = append(kept, t)
				}
			}
			if len(kept) == 1 {
				v["type"] = kept[0]
			} else {
				v["type"] = kept
			}
			if nullable {
				v["nullable"] = true
			}
		}
		for _, child := range v {
			downconvert(child)
		}
	case []any:
		for _, child := range v {
			downconvert(child)
		}
	}
}
