package secretbox_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/secretbox"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, secretbox.KeySize) }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func mustBox(t *testing.T, keys map[string][]byte, active string) *secretbox.Box {
	t.Helper()
	b, err := secretbox.New(keys, active)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	is := is.New(t)
	b := mustBox(t, map[string][]byte{"k1": key(1)}, "k1")
	aad := secretbox.AAD("registry", "auth_token", "row-1")

	stored, err := b.Encrypt([]byte("ghp_secret"), aad)
	is.NoErr(err)
	is.True(strings.HasPrefix(stored, "enc:v1:k1:"))
	is.True(!strings.Contains(stored, "ghp_secret"))

	got, legacy, err := b.Decrypt(stored, aad)
	is.NoErr(err)
	is.True(!legacy)
	is.Equal(string(got), "ghp_secret")

	again, err := b.Encrypt([]byte("ghp_secret"), aad)
	is.NoErr(err)
	is.True(again != stored) // fresh nonce per encryption
}

func TestDecryptFailures(t *testing.T) {
	b := mustBox(t, map[string][]byte{"k1": key(1)}, "k1")
	aad := secretbox.AAD("registry", "auth_token", "row-1")
	stored, err := b.Encrypt([]byte("ghp_secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.TrimPrefix(stored, "enc:v1:k1:")
	raw, _ := base64.StdEncoding.DecodeString(payload)
	raw[len(raw)-1] ^= 0xff
	other := mustBox(t, map[string][]byte{"k2": key(2)}, "k2")

	tests := []struct {
		name   string
		box    *secretbox.Box
		stored string
		aad    []byte
	}{
		{"wrong row", b, stored, secretbox.AAD("registry", "auth_token", "row-2")},
		{"wrong column", b, stored, secretbox.AAD("registry", "webhook_secret", "row-1")},
		{"tampered ciphertext", b, "enc:v1:k1:" + b64(raw), aad},
		{"unknown key id", other, stored, aad},
		{"key id swapped", mustBox(t, map[string][]byte{"k1": key(9)}, "k1"), stored, aad},
		{"no key configured", nil, stored, aad},
		{"missing payload separator", b, "enc:v1:k1", aad},
		{"bad base64", b, "enc:v1:k1:!!!", aad},
		{"too short", b, "enc:v1:k1:" + b64([]byte("short")), aad},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			_, _, err := tt.box.Decrypt(tt.stored, tt.aad)
			is.True(err != nil)
		})
	}
}

func TestRotation(t *testing.T) {
	is := is.New(t)
	aad := secretbox.AAD("registry", "webhook_secret", "row-1")
	old := mustBox(t, map[string][]byte{"k1": key(1)}, "k1")
	storedOld, err := old.Encrypt([]byte("s1"), aad)
	is.NoErr(err)

	ring := mustBox(t, map[string][]byte{"k1": key(1), "k2": key(2)}, "k2")
	storedNew, err := ring.Encrypt([]byte("s2"), aad)
	is.NoErr(err)
	is.Equal(secretbox.KeyID(storedNew), "k2")

	got, _, err := ring.Decrypt(storedOld, aad)
	is.NoErr(err)
	is.Equal(string(got), "s1")
	got, _, err = ring.Decrypt(storedNew, aad)
	is.NoErr(err)
	is.Equal(string(got), "s2")

	is.True(ring.NeedsRewrite(storedOld))
	is.True(!ring.NeedsRewrite(storedNew))
	is.True(ring.NeedsRewrite("legacy-plaintext"))
	is.True(!ring.NeedsRewrite(""))
	is.True(!(*secretbox.Box)(nil).NeedsRewrite("legacy-plaintext"))
}

func TestLegacyPassthrough(t *testing.T) {
	is := is.New(t)
	aad := secretbox.AAD("registry", "auth_token", "row-1")
	for _, b := range []*secretbox.Box{nil, mustBox(t, map[string][]byte{"k1": key(1)}, "k1")} {
		got, legacy, err := b.Decrypt("plain-token", aad)
		is.NoErr(err)
		is.True(legacy)
		is.Equal(string(got), "plain-token")
	}

	// A nil Box stores plaintext: the unconfigured, non-production mode.
	stored, err := (*secretbox.Box)(nil).Encrypt([]byte("plain-token"), aad)
	is.NoErr(err)
	is.Equal(stored, "plain-token")
}

func TestParse(t *testing.T) {
	k1, k2 := b64(key(1)), b64(key(2))
	tests := []struct {
		name       string
		keys       string
		active     string
		wantErr    bool
		wantNil    bool
		wantActive string
	}{
		{name: "unset", wantNil: true},
		{name: "single key", keys: "k1:" + k1, active: "k1", wantActive: "k1"},
		{name: "ring with spaces", keys: " k1:" + k1 + " , k2:" + k2, active: "k2", wantActive: "k2"},
		{name: "active without keys", active: "k1", wantErr: true},
		{name: "active missing", keys: "k1:" + k1, wantErr: true},
		{name: "active not in ring", keys: "k1:" + k1, active: "k2", wantErr: true},
		{name: "no separator", keys: "k1" + k1, active: "k1", wantErr: true},
		{name: "bad base64", keys: "k1:not-base64!", active: "k1", wantErr: true},
		{name: "short key", keys: "k1:" + b64(make([]byte, 16)), active: "k1", wantErr: true},
		{name: "duplicate id", keys: "k1:" + k1 + ",k1:" + k2, active: "k1", wantErr: true},
		{name: "bad id", keys: "k 1:" + k1, active: "k 1", wantErr: true},
		{name: "empty id", keys: ":" + k1, active: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			b, err := secretbox.Parse(tt.keys, tt.active)
			if tt.wantErr {
				is.True(err != nil)
				return
			}
			is.NoErr(err)
			is.Equal(b == nil, tt.wantNil)
			is.Equal(b.ActiveKey(), tt.wantActive)
		})
	}
}
