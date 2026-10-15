package tests

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
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

// TestEncryptRegistrySecrets pins `ocidex migrate encrypt-secrets`: legacy
// plaintext is sealed, values under an old key move to the active one,
// --dry-run writes nothing, and a second run changes nothing.
func TestEncryptRegistrySecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)

	is := is.New(t)
	ctx := t.Context()
	pool, cleanDB := setupTestDB(t)
	defer cleanDB()

	k1, k2 := bytes.Repeat([]byte{1}, secretbox.KeySize), bytes.Repeat([]byte{2}, secretbox.KeySize)
	oldBox, err := secretbox.New(map[string][]byte{"k1": k1}, "k1")
	is.NoErr(err)
	ring, err := secretbox.New(map[string][]byte{"k1": k1, "k2": k2}, "k2")
	is.NoErr(err)

	create := func(svc service.RegistryService, name, token, secret string) string {
		t.Helper()
		reg, err := svc.Create(ctx, service.CreateRegistryParams{
			Name: name, Type: "generic", URL: "https://" + name + ".example.com", ScanMode: "webhook",
			AuthToken: &token, WebhookSecret: &secret,
		})
		is.NoErr(err)
		return reg.ID
	}
	legacyID := create(service.NewRegistryService(pool, nil), "legacy", "legacy-token", "legacy-secret")
	oldKeyID := create(service.NewRegistryService(pool, oldBox), "oldkey", "oldkey-token", "oldkey-secret")
	tokenOnly := "only-token"
	_, err = service.NewRegistryService(pool, nil).Create(ctx, service.CreateRegistryParams{
		Name: "tokenonly", Type: "generic", URL: "https://tokenonly.example.com", ScanMode: "poll",
		PollIntervalMinutes: 60, AuthToken: &tokenOnly,
	})
	is.NoErr(err)

	repo := repository.New(pool)
	stored := func(id string) (string, string) {
		t.Helper()
		var tok, sec string
		is.NoErr(pool.QueryRow(ctx, `SELECT auth_token, webhook_secret FROM registry WHERE id = $1::uuid`, id).Scan(&tok, &sec))
		return tok, sec
	}

	// A batch size of 2 forces keyset paging across the three rows.
	dry, err := service.EncryptRegistrySecrets(ctx, repo, ring, 2, true)
	is.NoErr(err)
	is.Equal(dry.Encrypted, 3) // legacy token+secret, tokenonly token
	is.Equal(dry.Rotated, 2)
	tok, _ := stored(legacyID)
	is.Equal(tok, "legacy-token") // dry run wrote nothing

	res, err := service.EncryptRegistrySecrets(ctx, repo, ring, 2, false)
	is.NoErr(err)
	is.Equal(res.Encrypted, 3)
	is.Equal(res.Rotated, 2)
	is.Equal(res.Current, 0)
	is.Equal(res.Conflicted, 0)
	is.Equal(len(res.Unreadable), 0)

	for _, id := range []string{legacyID, oldKeyID} {
		tok, sec := stored(id)
		is.True(strings.HasPrefix(tok, "enc:v1:k2:"))
		is.True(strings.HasPrefix(sec, "enc:v1:k2:"))
	}
	svc := service.NewRegistryService(pool, ring)
	got, err := svc.Get(ctx, legacyID)
	is.NoErr(err)
	is.Equal(*got.AuthToken, "legacy-token")
	is.Equal(*got.WebhookSecret, "legacy-secret")
	got, err = svc.Get(ctx, oldKeyID)
	is.NoErr(err)
	is.Equal(*got.AuthToken, "oldkey-token")

	again, err := service.EncryptRegistrySecrets(ctx, repo, ring, 2, false)
	is.NoErr(err)
	is.Equal(again.Encrypted, 0)
	is.Equal(again.Rotated, 0)
	is.Equal(again.Current, 5)
}
