package output

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"
)

// newTabWriter is the one place the table's spacing is decided.
func newTabWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
}

// renderTable prints one row per item. An empty result set still prints the
// header row: a table with no rows under a header reads as "none", whereas no
// output at all reads as "the command did nothing".
func renderTable[T any](w io.Writer, items []T, cols []Column[T]) error {
	if len(cols) == 0 {
		cols = deriveColumns[T]()
	}
	if len(cols) == 0 {
		return fmt.Errorf("no table columns for %T", *new(T))
	}

	tw := newTabWriter(w)
	headers := make([]string, len(cols))
	for i, c := range cols {
		headers[i] = c.Header
	}
	fmt.Fprintln(tw, strings.Join(headers, "\t"))

	for _, item := range items {
		cells := make([]string, len(cols))
		for i, c := range cols {
			if c.Value != nil {
				cells[i] = c.Value(item)
			}
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

// renderFields prints a single item as aligned key/value lines.
func renderFields[T any](w io.Writer, item T, fields []Column[T]) error {
	if len(fields) == 0 {
		fields = deriveColumns[T]()
	}
	if len(fields) == 0 {
		return fmt.Errorf("no fields to render for %T", item)
	}

	tw := newTabWriter(w)
	for _, f := range fields {
		var value string
		if f.Value != nil {
			value = f.Value(item)
		}
		fmt.Fprintf(tw, "%s:\t%s\n", f.Header, value)
	}
	return tw.Flush()
}

// deriveColumns builds columns from T's exported fields, in declaration order,
// naming each from its json tag so the table and `-o json` agree on what a
// field is called.
//
// Fields whose value cannot be put in a cell — nested structs, maps, slices of
// structs — are skipped rather than rendered blank. They are why `-o json`
// exists; a column of empty cells would only suggest the data is missing.
func deriveColumns[T any]() []Column[T] {
	t := reflect.TypeOf((*T)(nil)).Elem()
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}

	var cols []Column[T]
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() || field.Anonymous {
			continue
		}
		name, ok := jsonName(field.Tag.Get("json"), field.Name)
		if !ok || !renderableType(field.Type) {
			continue
		}

		index := i
		cols = append(cols, Column[T]{
			Header: header(name),
			Value: func(item T) string {
				v := reflect.ValueOf(item)
				for v.Kind() == reflect.Pointer {
					if v.IsNil() {
						return ""
					}
					v = v.Elem()
				}
				return formatValue(v.Field(index))
			},
		})
	}
	return cols
}

// jsonName returns the field's wire name, and whether it is rendered at all.
func jsonName(tag, fallback string) (string, bool) {
	name, _, _ := strings.Cut(tag, ",")
	switch name {
	case "-":
		return "", false
	case "":
		return fallback, true
	default:
		return name, true
	}
}

// header turns a wire name into a column heading: componentCount -> COMPONENT COUNT.
func header(name string) string {
	var b strings.Builder
	for i, r := range name {
		switch {
		case r == '_' || r == '-':
			b.WriteRune(' ')
		case r >= 'A' && r <= 'Z' && i > 0:
			b.WriteRune(' ')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}

var timeType = reflect.TypeOf(time.Time{})

// cellKinds are the kinds whose values read sensibly in a single table cell.
var cellKinds = map[reflect.Kind]bool{
	reflect.String: true, reflect.Bool: true,
	reflect.Int: true, reflect.Int8: true, reflect.Int16: true,
	reflect.Int32: true, reflect.Int64: true,
	reflect.Uint: true, reflect.Uint8: true, reflect.Uint16: true,
	reflect.Uint32: true, reflect.Uint64: true,
	reflect.Float32: true, reflect.Float64: true,
}

// renderableType reports whether a value of type t fits in a table cell.
func renderableType(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == timeType {
		return true
	}
	// A slice becomes one comma-joined cell; a slice of slices does not.
	if k := t.Kind(); k == reflect.Slice || k == reflect.Array {
		return renderableType(t.Elem()) && t.Elem().Kind() != reflect.Slice
	}
	return cellKinds[t.Kind()]
}

// formatValue renders one cell. An unset pointer is an empty cell, not "<nil>".
func formatValue(v reflect.Value) string {
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return ""
	}
	if v.Type() == timeType {
		return v.Interface().(time.Time).Format(time.RFC3339)
	}

	k := v.Kind()
	if k == reflect.String {
		return v.String()
	}
	if k == reflect.Float32 || k == reflect.Float64 {
		// %g so 1.0 renders as "1", not "1.000000".
		return fmt.Sprintf("%g", v.Float())
	}
	if k == reflect.Slice || k == reflect.Array {
		parts := make([]string, v.Len())
		for i := range v.Len() {
			parts[i] = formatValue(v.Index(i))
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(v.Interface())
}
