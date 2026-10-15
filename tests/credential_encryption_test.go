package tests

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/secretbox"
	"github.com/pfenerty/ocidex/internal/service"
)

// TestRegistryCredentialsEncryptedAtRest proves the ADR-051 promise against a
// real database: the registry columns hold ciphertext, every consumer gets
// plaintext — including the scan job claim the scanner authenticates with —
// and rows written before encryption keep working.
func TestRegistryCredentialsEncryptedAtRest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	is := is.New(t)
	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	box, err := secretbox.New(map[string][]byte{"k1": bytes.Repeat([]byte{3}, secretbox.KeySize)}, "k1")
	is.NoErr(err)
	regSvc := service.NewRegistryService(pool, box)
	jobSvc := service.NewJobService(pool, box)

	token, secret := "ghp_integration_token", "integration-webhook-secret"
	reg, err := regSvc.Create(ctx, service.CreateRegistryParams{
		Name: "enc-test", Type: "generic", URL: "https://registry.example.com", ScanMode: "webhook",
		AuthUsername: &[]string{"bot"}[0], AuthToken: &token, WebhookSecret: &secret,
	})
	is.NoErr(err)

	readColumns := func() (string, string) {
		t.Helper()
		var storedToken, storedSecret string
		err := pool.QueryRow(ctx, `SELECT auth_token, webhook_secret FROM registry WHERE id = $1::uuid`, reg.ID).
			Scan(&storedToken, &storedSecret)
		is.NoErr(err)
		return storedToken, storedSecret
	}

	t.Run("columns hold ciphertext", func(t *testing.T) {
		is := is.New(t)
		storedToken, storedSecret := readColumns()
		is.True(strings.HasPrefix(storedToken, "enc:v1:k1:"))
		is.True(strings.HasPrefix(storedSecret, "enc:v1:k1:"))
		is.True(!strings.Contains(storedToken, token))
		is.True(!strings.Contains(storedSecret, secret))
	})

	claimToken := func(t *testing.T, digest string) string {
		t.Helper()
		job, err := jobSvc.Enqueue(ctx, reg.ID, "app", digest, "", "latest", "")
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		claim, ok, err := jobSvc.ClaimByID(ctx, job.ID, "test-worker")
		if err != nil || !ok {
			t.Fatalf("claim: ok=%v err=%v", ok, err)
		}
		return claim.AuthToken
	}

	t.Run("consumers see plaintext", func(t *testing.T) {
		is := is.New(t)
		got, err := regSvc.Get(ctx, reg.ID)
		is.NoErr(err)
		is.Equal(*got.AuthToken, token)
		is.Equal(*got.WebhookSecret, secret)
		// The scan claim is what the scanner hands syft and the registry client.
		is.Equal(claimToken(t, "sha256:"+strings.Repeat("a", 64)), token)
	})

	t.Run("legacy plaintext rows keep working", func(t *testing.T) {
		is := is.New(t)
		_, err := pool.Exec(ctx, `UPDATE registry SET auth_token = 'legacy-token', webhook_secret = 'legacy-secret' WHERE id = $1::uuid`, reg.ID)
		is.NoErr(err)
		got, err := regSvc.Get(ctx, reg.ID)
		is.NoErr(err)
		is.Equal(*got.AuthToken, "legacy-token")
		is.Equal(*got.WebhookSecret, "legacy-secret")
		is.Equal(claimToken(t, "sha256:"+strings.Repeat("b", 64)), "legacy-token")
	})
}
