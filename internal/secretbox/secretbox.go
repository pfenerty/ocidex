// Package secretbox encrypts credentials stored in the database (ADR-051).
//
// A stored value is "enc:v1:<key-id>:<base64(nonce||ciphertext||tag)>",
// sealed with AES-256-GCM under the named key. The AAD binds the value to the
// table, column and row it was written for, so a ciphertext copied elsewhere
// fails to decrypt. A value without the prefix is legacy plaintext, returned
// unchanged and flagged so callers can tell it apart.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Prefix marks a value encrypted in the v1 format.
const Prefix = "enc:v1:"

// KeySize is the required key length: AES-256.
const KeySize = 32

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// Box encrypts with its active key and decrypts with any key in its ring.
// A nil *Box encrypts nothing (Encrypt returns the plaintext) and refuses to
// decrypt an encrypted value; that is the unconfigured, non-production mode.
type Box struct {
	active string
	keys   map[string]cipher.AEAD
}

// New builds a Box from a key ring of id → 32-byte key and the active id.
func New(keys map[string][]byte, active string) (*Box, error) {
	if len(keys) == 0 {
		return nil, errors.New("no keys")
	}
	b := &Box{active: active, keys: make(map[string]cipher.AEAD, len(keys))}
	for id, key := range keys {
		if !keyIDPattern.MatchString(id) {
			return nil, fmt.Errorf("key id %q: must match %s", id, keyIDPattern)
		}
		if len(key) != KeySize {
			return nil, fmt.Errorf("key %q: must be %d bytes, got %d", id, KeySize, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", id, err)
		}
		b.keys[id] = aead
	}
	if _, ok := b.keys[active]; !ok {
		return nil, fmt.Errorf("active key %q is not in the key list", active)
	}
	return b, nil
}

// Parse builds a Box from DATA_ENCRYPTION_KEYS ("<id>:<base64 key>,...") and
// DATA_ENCRYPTION_ACTIVE_KEY. An empty keys string returns a nil Box.
func Parse(rawKeys, active string) (*Box, error) {
	rawKeys = strings.TrimSpace(rawKeys)
	if rawKeys == "" {
		if active != "" {
			return nil, errors.New("active key set but no keys configured")
		}
		return nil, nil
	}
	keys := map[string][]byte{}
	for _, entry := range strings.Split(rawKeys, ",") {
		id, enc, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			return nil, fmt.Errorf("entry %q: want <id>:<base64 key>", entry)
		}
		if _, dup := keys[id]; dup {
			return nil, fmt.Errorf("duplicate key id %q", id)
		}
		key, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return nil, fmt.Errorf("key %q: invalid base64: %w", id, err)
		}
		keys[id] = key
	}
	return New(keys, active)
}

// ActiveKey returns the id new values are encrypted with.
func (b *Box) ActiveKey() string {
	if b == nil {
		return ""
	}
	return b.active
}

// Encrypt seals plaintext under the active key, bound to aad. A nil Box
// returns the plaintext unchanged.
func (b *Box) Encrypt(plaintext, aad []byte) (string, error) {
	if b == nil {
		return string(plaintext), nil
	}
	aead := b.keys[b.active]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	sealed := aead.Seal(nonce, nonce, plaintext, aad)
	return Prefix + b.active + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a stored value. A value without the enc:v1: prefix is legacy
// plaintext: it is returned unchanged with legacy=true. An encrypted value
// that is malformed, names an unknown key, or fails authentication is an error.
func (b *Box) Decrypt(stored string, aad []byte) (plaintext []byte, legacy bool, err error) {
	if !IsEncrypted(stored) {
		return []byte(stored), true, nil
	}
	if b == nil {
		return nil, false, errors.New("encrypted value but no encryption key configured")
	}
	id, payload, ok := strings.Cut(strings.TrimPrefix(stored, Prefix), ":")
	if !ok {
		return nil, false, errors.New("malformed encrypted value")
	}
	aead, ok := b.keys[id]
	if !ok {
		return nil, false, fmt.Errorf("unknown encryption key %q", id)
	}
	sealed, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, false, fmt.Errorf("malformed encrypted value: %w", err)
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, false, errors.New("malformed encrypted value: too short")
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	out, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, false, errors.New("decrypting value: authentication failed")
	}
	return out, false, nil
}

// NeedsRewrite reports whether a stored value should be re-encrypted: it is
// legacy plaintext, or it was sealed under a key other than the active one.
// A nil Box never asks for a rewrite.
func (b *Box) NeedsRewrite(stored string) bool {
	if b == nil || stored == "" {
		return false
	}
	return KeyID(stored) != b.active
}

// IsEncrypted reports whether a stored value is in the enc:v1 format.
func IsEncrypted(stored string) bool {
	return strings.HasPrefix(stored, Prefix)
}

// KeyID returns the key id an encrypted value names, or "" for plaintext.
func KeyID(stored string) string {
	if !IsEncrypted(stored) {
		return ""
	}
	id, _, _ := strings.Cut(strings.TrimPrefix(stored, Prefix), ":")
	return id
}

// AAD returns the additional authenticated data binding a value to a
// table column and row: "<table>.<column>:<rowID>".
func AAD(table, column, rowID string) []byte {
	return []byte(table + "." + column + ":" + rowID)
}
