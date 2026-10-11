package gosymbols

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/matryer/is"
)

func TestPropertiesRoundTrip(t *testing.T) {
	is := is.New(t)
	in := Table{
		"net/http": {"Get", "(*Server).Serve"},
		"unsafe":   {}, // present, no symbols
	}
	props := append([]cdx.Property{{Name: "syft:package:type", Value: "go-module"}}, Properties(in)...)
	is.Equal(props[1], cdx.Property{Name: "ocidex:go:symbols:net/http", Value: "(*Server).Serve Get"})
	is.Equal(props[2], cdx.Property{Name: "ocidex:go:symbols:unsafe", Value: ""})

	got, rest := FromProperties(props)
	is.Equal(rest, []cdx.Property{{Name: "syft:package:type", Value: "go-module"}})
	is.Equal(got["net/http"], []string{"(*Server).Serve", "Get"})
	_, present := got["unsafe"]
	is.True(present)
}

func TestFromPropertiesNoSymbols(t *testing.T) {
	is := is.New(t)
	got, rest := FromProperties([]cdx.Property{{Name: "a", Value: "b"}})
	is.True(got == nil)
	is.Equal(len(rest), 1)
}

func TestStrip(t *testing.T) {
	is := is.New(t)
	sym := Properties(Table{"os": {"Open"}})
	keep := []cdx.Property{{Name: "syft:package:type", Value: "go-module"}}
	both := append(append([]cdx.Property{}, keep...), sym...)
	nested := []cdx.Component{{Name: "inner", Properties: &sym}}
	bom := &cdx.BOM{Components: &[]cdx.Component{
		{Name: "a", Properties: &both, Components: &nested},
		{Name: "b"},
	}}
	is.True(Strip(bom))
	comps := *bom.Components
	is.Equal(*comps[0].Properties, keep)
	is.True((*comps[0].Components)[0].Properties == nil) // only symbols: property list removed
	is.True(!Strip(bom))                                 // idempotent
}

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		"Get":                       "Get",
		"(*Server).Serve":           "Server.Serve",
		"(*Server).Serve-fm":        "Server.Serve",
		"(*Map[go.shape.int]).Load": "Map.Load",
		"Conn.Read":                 "Conn.Read",
	}
	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			is.New(t).Equal(Normalize(in), want)
		})
	}
}

func TestNormalized(t *testing.T) {
	is := is.New(t)
	got := Normalized(Table{
		"net/http": {"(*Server).Serve", "(*Server).Serve-fm", "Get"},
		"unsafe":   nil,
	})
	is.Equal(got["net/http"], []string{"Get", "Server.Serve"})
	v, ok := got["unsafe"]
	is.True(ok)
	is.Equal(len(v), 0)
}
