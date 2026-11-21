package uuidx_test

import (
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/uuidx"
)

func TestParseRoundTrip(t *testing.T) {
	for _, s := range []string{
		"0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6b",
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
	} {
		t.Run(s, func(t *testing.T) {
			is := is.New(t)
			id, err := uuidx.Parse(s)
			is.NoErr(err)
			is.True(id.Valid)
			is.Equal(id.String(), s)
		})
	}
}

func TestParseAcceptsUndashedAndUppercase(t *testing.T) {
	is := is.New(t)
	id, err := uuidx.Parse("0B7E3C1A9F204D5E8A6B1C2D3E4F5A6B")
	is.NoErr(err)
	is.Equal(id.String(), "0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6b")
}

func TestParseInvalid(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-uuid",
		"0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6",   // one short
		"0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6bb", // one long
		"0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6g",  // not hex
		strings.Repeat("a", 36),                 // pgx's Scan alone took this
		"0b7e3c1a9-f20-4d5e-8a6b-1c2d3e4f5a6b",  // dash in the wrong place
	} {
		t.Run(s, func(t *testing.T) {
			is := is.New(t)
			id, err := uuidx.Parse(s)
			is.True(err != nil)
			is.True(!id.Valid)
		})
	}
}

func TestOrNull(t *testing.T) {
	is := is.New(t)
	is.True(!uuidx.OrNull("").Valid)
	is.True(!uuidx.OrNull("nope").Valid)
	id := uuidx.OrNull("0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6b")
	is.True(id.Valid)
	is.Equal(id.String(), "0b7e3c1a-9f20-4d5e-8a6b-1c2d3e4f5a6b")
}
