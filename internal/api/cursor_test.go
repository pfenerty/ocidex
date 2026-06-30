package api

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestTimeIDCursorRoundTrip(t *testing.T) {
	is := is.New(t)

	created := time.Date(2026, 6, 30, 12, 34, 56, 0, time.UTC)
	id := "3e671687-395b-41f5-a30f-a58921a69b79"

	enc := encodeTimeIDCursor(created, id)
	is.True(enc != "")

	cur, ok, err := decodeTimeIDCursor(enc)
	is.NoErr(err)
	is.True(ok)
	is.True(cur.CreatedAt.Equal(created))
	is.Equal(cur.ID, id)
}

func TestDecodeEmptyCursor(t *testing.T) {
	is := is.New(t)

	_, ok, err := decodeTimeIDCursor("")
	is.NoErr(err)
	is.Equal(ok, false)
}

func TestDecodeInvalidCursor(t *testing.T) {
	is := is.New(t)

	_, _, err := decodeTimeIDCursor("!!!not-base64!!!")
	is.True(err != nil)
}
