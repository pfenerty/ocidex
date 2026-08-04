package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/matryer/is"
)

// sbomRow stands in for an API list item: json tags, a pointer field, a time,
// and a nested struct that cannot go in a table cell.
type sbomRow struct {
	ID             string             `json:"id"`
	ComponentCount int                `json:"componentCount"`
	Version        *string            `json:"version,omitempty"`
	Tags           []string           `json:"tags"`
	CreatedAt      time.Time          `json:"createdAt"`
	Meta           struct{ A string } `json:"meta"`
	Internal       string             `json:"-"`
}

func rows() []sbomRow {
	v := "v1.2.3"
	return []sbomRow{
		{
			ID:             "abc",
			ComponentCount: 2,
			Version:        &v,
			Tags:           []string{"latest", "edge"},
			CreatedAt:      time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC),
			Internal:       "hidden",
		},
		{ID: "def", ComponentCount: 0},
	}
}

func render(t *testing.T, f Format, items []sbomRow, cols ...Column[sbomRow]) string {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := List(buf, f, items, cols...); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestListTableDerivedColumns(t *testing.T) {
	is := is.New(t)
	out := render(t, Table, rows())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	is.Equal(len(lines), 3) // header + two rows

	// Headers come from json tags, camelCase split and upper-cased.
	is.True(strings.Contains(lines[0], "ID"))
	is.True(strings.Contains(lines[0], "COMPONENT COUNT"))
	is.True(strings.Contains(lines[0], "CREATED AT"))
	// json:"-" is not a column, and neither is a nested struct.
	is.True(!strings.Contains(lines[0], "INTERNAL"))
	is.True(!strings.Contains(lines[0], "META"))

	is.True(strings.Contains(lines[1], "v1.2.3"))
	is.True(strings.Contains(lines[1], "latest,edge"))
	is.True(strings.Contains(lines[1], "2026-08-02T12:00:00Z"))
	// An unset pointer is an empty cell, not "<nil>".
	is.True(!strings.Contains(lines[2], "nil"))
}

func TestListTableExplicitColumns(t *testing.T) {
	is := is.New(t)
	out := render(t, Table, rows(), Column[sbomRow]{
		Header: "SBOM",
		Value:  func(r sbomRow) string { return r.ID },
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	is.Equal(lines[0], "SBOM")
	is.Equal(strings.TrimSpace(lines[1]), "abc")
}

// An empty result still prints the header: a header with no rows reads as
// "none", where no output at all reads as "the command did nothing".
func TestListTableEmpty(t *testing.T) {
	is := is.New(t)
	out := render(t, Table, nil)
	is.Equal(len(strings.Split(strings.TrimRight(out, "\n"), "\n")), 1)
}

// A nil slice must encode as [] so `jq` gets an array either way.
func TestListJSONEmptyIsArray(t *testing.T) {
	is := is.New(t)
	is.Equal(strings.TrimSpace(render(t, JSON, nil)), "[]")
	is.Equal(strings.TrimSpace(render(t, YAML, nil)), "[]")
}

func TestListJSONUsesWireNames(t *testing.T) {
	is := is.New(t)
	out := render(t, JSON, rows()[:1])
	is.True(strings.Contains(out, `"componentCount": 2`))
	is.True(!strings.Contains(out, "hidden"))
}

// YAML goes through the json tags too, so the two encodings name fields the
// same way — the reason this package uses sigs.k8s.io/yaml.
func TestListYAMLUsesWireNames(t *testing.T) {
	is := is.New(t)
	out := render(t, YAML, rows()[:1])
	is.True(strings.Contains(out, "componentCount: 2"))
	is.True(!strings.Contains(out, "componentcount"))
}

func TestItemTableIsKeyValue(t *testing.T) {
	is := is.New(t)
	buf := &bytes.Buffer{}
	is.NoErr(Item(buf, Table, rows()[0]))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	is.True(len(lines) > 1)
	is.True(strings.HasPrefix(lines[0], "ID:"))
	is.True(strings.Contains(lines[0], "abc"))
}

func TestUnknownFormat(t *testing.T) {
	is := is.New(t)
	is.True(List(&bytes.Buffer{}, Format("xml"), rows()) != nil)
	is.True(Item(&bytes.Buffer{}, Format("xml"), rows()[0]) != nil)
	is.True(!Valid(Format("xml")))
	is.True(!Valid(Format("")))
	is.True(Valid(Table))
}
