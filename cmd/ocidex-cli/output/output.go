// Package output renders command results in the format selected by --output.
//
// Subcommands hand a value and, optionally, a column definition to List or
// Item; they never format anything themselves. That is what makes every new
// command support all three formats without extra work, and what keeps the JSON
// and YAML output identical to the API's own response shape.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"sigs.k8s.io/yaml"
)

// Format is the rendering mode chosen by --output.
type Format string

const (
	Table Format = "table"
	JSON  Format = "json"
	YAML  Format = "yaml"
)

// Valid reports whether f is a format this package can render. The empty string
// is not valid; callers resolve their default before rendering.
func Valid(f Format) bool {
	switch f {
	case Table, JSON, YAML:
		return true
	default:
		return false
	}
}

// Column is one column of a table, or one row of a single item's key/value
// view. A nil Value is treated as an empty cell.
type Column[T any] struct {
	Header string
	Value  func(T) string
}

// List renders a slice of results.
//
// With no columns, they are derived from T's exported fields and json tags, so
// a new command gets a usable table for free; pass columns to curate which
// fields appear and in what order. JSON and YAML ignore columns entirely and
// encode the items as the API returned them.
func List[T any](w io.Writer, f Format, items []T, cols ...Column[T]) error {
	switch f {
	case JSON, YAML:
		// A nil slice encodes as null, which is a worse thing for `jq` to
		// receive than an empty array.
		if items == nil {
			items = []T{}
		}
		return encode(w, f, items)
	case Table:
		return renderTable(w, items, cols)
	default:
		return fmt.Errorf("unknown output format %q", f)
	}
}

// Item renders a single result. In table mode it is a key/value view rather
// than a one-row table, because a single object's fields are read down, not
// across.
func Item[T any](w io.Writer, f Format, item T, fields ...Column[T]) error {
	switch f {
	case JSON, YAML:
		return encode(w, f, item)
	case Table:
		return renderFields(w, item, fields)
	default:
		return fmt.Errorf("unknown output format %q", f)
	}
}

func encode(w io.Writer, f Format, v any) error {
	if f == YAML {
		// sigs.k8s.io/yaml, not gopkg.in/yaml.v3: the API types carry json tags
		// only, so a direct YAML marshal would emit lowercased Go field names
		// (componentcount) instead of the documented ones (componentCount).
		data, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Errorf("rendering yaml: %w", err)
		}
		_, err = w.Write(data)
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("rendering json: %w", err)
	}
	return nil
}
