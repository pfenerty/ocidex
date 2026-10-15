package service

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/secretbox"
)

// Registry columns encrypted at rest (ADR-051). The column name is part of the
// AAD, so a value moved between them fails to decrypt.
const (
	colAuthToken     = "auth_token"
	colWebhookSecret = "webhook_secret"
)

// registryAAD binds a stored credential to its column and registry row.
func registryAAD(column, registryID string) []byte {
	return secretbox.AAD("registry", column, registryID)
}

// sealCredential encrypts a credential for storage in a registry column. A nil
// value stays NULL; a nil Box stores the plaintext (non-production, ADR-051).
func sealCredential(box *secretbox.Box, column, registryID string, v *string) (pgtype.Text, error) {
	if v == nil {
		return pgtype.Text{}, nil
	}
	if *v == "" {
		return pgtype.Text{String: "", Valid: true}, nil
	}
	stored, err := box.Encrypt([]byte(*v), registryAAD(column, registryID))
	if err != nil {
		return pgtype.Text{}, fmt.Errorf("encrypting registry %s: %w", column, err)
	}
	return pgtype.Text{String: stored, Valid: true}, nil
}

// openCredential decrypts a stored credential. Legacy plaintext is returned
// as-is until `ocidex migrate encrypt-secrets` rewrites it.
func openCredential(box *secretbox.Box, column, registryID, stored string) (string, error) {
	pt, _, err := box.Decrypt(stored, registryAAD(column, registryID))
	if err != nil {
		return "", fmt.Errorf("registry %s %s: %w", registryID, column, err)
	}
	return string(pt), nil
}

// decryptCredentials replaces r's stored credentials with their plaintext.
// Everything above the service layer sees plaintext only.
func decryptCredentials(box *secretbox.Box, r Registry) (Registry, error) {
	for _, f := range []struct {
		column string
		v      **string
	}{{colAuthToken, &r.AuthToken}, {colWebhookSecret, &r.WebhookSecret}} {
		if *f.v == nil {
			continue
		}
		pt, err := openCredential(box, f.column, r.ID, **f.v)
		if err != nil {
			return Registry{}, err
		}
		*f.v = &pt
	}
	return r, nil
}
