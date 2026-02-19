package service

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"
)

func TestUUIDToString(t *testing.T) {
	tests := []struct {
		name string
		id   pgtype.UUID
		want string
	}{
		{
			"valid",
			pgtype.UUID{Bytes: [16]byte{0x3e, 0x67, 0x16, 0x87, 0x39, 0x5b, 0x41, 0xf5, 0xa3, 0x0f, 0xa5, 0x89, 0x21, 0xa6, 0x9b, 0x79}, Valid: true},
			"3e671687-395b-41f5-a30f-a58921a69b79",
		},
		{"invalid", pgtype.UUID{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(uuidToString(tt.id), tt.want)
		})
	}
}

func TestTextToPtr(t *testing.T) {
	tests := []struct {
		name    string
		input   pgtype.Text
		wantNil bool
		wantVal string
	}{
		{"valid", pgtype.Text{String: "hello", Valid: true}, false, "hello"},
		{"null", pgtype.Text{}, true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			result := textToPtr(tt.input)
			if tt.wantNil {
				is.True(result == nil)
			} else {
				is.True(result != nil)
				is.Equal(*result, tt.wantVal)
			}
		})
	}
}
