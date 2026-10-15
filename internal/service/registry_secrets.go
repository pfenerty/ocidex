package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
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

// RegistrySecretsRepository is the slice of the repository the re-encrypt
// pass needs.
type RegistrySecretsRepository interface {
	ListRegistrySecretsPage(ctx context.Context, arg repository.ListRegistrySecretsPageParams) ([]repository.ListRegistrySecretsPageRow, error)
	RewriteRegistrySecrets(ctx context.Context, arg repository.RewriteRegistrySecretsParams) (int64, error)
}

// EncryptSecretsResult counts what EncryptRegistrySecrets did, per value.
type EncryptSecretsResult struct {
	Encrypted int // legacy plaintext sealed under the active key
	Rotated   int // re-sealed from an older key to the active one
	Current   int // already under the active key
	// Conflicted rows changed between read and write; the next run picks
	// them up.
	Conflicted int
	// Unreadable values could not be decrypted (unknown key or tampering).
	// They are left as-is; the registry's credentials must be re-entered.
	Unreadable []string
}

// EncryptRegistrySecrets seals every legacy plaintext registry credential
// and re-seals every one under a non-active key (ADR-051). It is idempotent:
// a second run finds every value Current. With dryRun it counts without
// writing.
func EncryptRegistrySecrets(ctx context.Context, repo RegistrySecretsRepository, box *secretbox.Box, batchSize int32, dryRun bool) (EncryptSecretsResult, error) {
	var res EncryptSecretsResult
	after := pgtype.UUID{Valid: true}
	for {
		rows, err := repo.ListRegistrySecretsPage(ctx, repository.ListRegistrySecretsPageParams{After: after, RowLimit: batchSize})
		if err != nil {
			return res, fmt.Errorf("listing registry credentials: %w", err)
		}
		for _, row := range rows {
			if err := rewriteRow(ctx, repo, box, row, dryRun, &res); err != nil {
				return res, err
			}
		}
		if len(rows) < int(batchSize) {
			return res, nil
		}
		after = rows[len(rows)-1].ID
	}
}

func rewriteRow(ctx context.Context, repo RegistrySecretsRepository, box *secretbox.Box, row repository.ListRegistrySecretsPageRow, dryRun bool, res *EncryptSecretsResult) error {
	id := uuidToStr(row.ID)
	newToken, tokenChanged := reseal(box, colAuthToken, id, row.AuthToken, res)
	newSecret, secretChanged := reseal(box, colWebhookSecret, id, row.WebhookSecret, res)
	if (!tokenChanged && !secretChanged) || dryRun {
		return nil
	}
	n, err := repo.RewriteRegistrySecrets(ctx, repository.RewriteRegistrySecretsParams{
		ID:               row.ID,
		NewAuthToken:     newToken,
		NewWebhookSecret: newSecret,
		OldAuthToken:     row.AuthToken,
		OldWebhookSecret: row.WebhookSecret,
	})
	if err != nil {
		return fmt.Errorf("rewriting registry %s credentials: %w", id, err)
	}
	if n == 0 {
		res.Conflicted++
	}
	return nil
}

// reseal returns stored re-sealed under the active key and whether it
// changed. A value it cannot read is recorded in res.Unreadable and returned
// unchanged.
func reseal(box *secretbox.Box, column, registryID string, stored pgtype.Text, res *EncryptSecretsResult) (pgtype.Text, bool) {
	if !stored.Valid || stored.String == "" {
		return stored, false
	}
	if !box.NeedsRewrite(stored.String) {
		res.Current++
		return stored, false
	}
	aad := registryAAD(column, registryID)
	pt, legacy, err := box.Decrypt(stored.String, aad)
	if err != nil {
		res.Unreadable = append(res.Unreadable, registryID+" "+column)
		return stored, false
	}
	sealed, err := box.Encrypt(pt, aad)
	if err != nil {
		res.Unreadable = append(res.Unreadable, registryID+" "+column)
		return stored, false
	}
	if legacy {
		res.Encrypted++
	} else {
		res.Rotated++
	}
	return pgtype.Text{String: sealed, Valid: true}, true
}
