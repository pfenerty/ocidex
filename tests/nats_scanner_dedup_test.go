package tests

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/scanner"
)

type fakeScanProcessor struct {
	mu        sync.Mutex
	calls     []scanner.ScanRequest
	failFirst bool
}

func (f *fakeScanProcessor) ProcessOne(_ context.Context, req scanner.ScanRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.failFirst && len(f.calls) == 1 {
		return errors.New("simulated processing failure")
	}
	return nil
}

func (f *fakeScanProcessor) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func setupScannerNATSClient(t *testing.T) (*natspkg.Client, func()) {
	t.Helper()
	ctx := t.Context()

	natsContainer, err := natsc.Run(ctx, "docker.io/nats:latest")
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}

	natsURL, err := natsContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats connection string: %v", err)
	}

	client, err := natspkg.Connect(natspkg.Config{
		URL:           natsURL,
		StreamName:    "ocidex",
		EventTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}

	cleanup := func() {
		client.Close()
		_ = natsContainer.Terminate(ctx)
	}
	return client, cleanup
}

// TestNATS_ScannerDedup verifies the two key idempotency guarantees of the NATS scan pipeline.
func TestNATS_ScannerDedup(t *testing.T) {
	requireDocker(t)

	// Sub-test A: publish-side dedup via Nats-Msg-Id.
	// Submitting the same registry+digest twice within the duplicate window must result in
	// exactly one ProcessOne call because JetStream discards the second publication.
	t.Run("publish_side", func(t *testing.T) {
		client, cleanup := setupScannerNATSClient(t)
		t.Cleanup(cleanup)

		fake := &fakeScanProcessor{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		ext := scanner.NewNATSExtension(client, fake, "ocidex", logger, nil, 5*time.Minute)

		extCtx, extCancel := context.WithCancel(t.Context())
		t.Cleanup(extCancel)
		if err := ext.Start(extCtx); err != nil {
			t.Fatalf("start extension: %v", err)
		}

		submitter := scanner.NewNATSSubmitter(client, "ocidex", nil)
		req := scanner.ScanRequest{
			RegistryURL: "registry.example.com",
			Repository:  "library/alpine",
			Digest:      "sha256:abc123dedup",
			RegistryID:  "00000000-0000-0000-0000-000000000001",
		}

		// Submit twice — identical RegistryID+Digest → same Nats-Msg-Id.
		if err := submitter.Submit(t.Context(), req); err != nil {
			t.Fatalf("first submit: %v", err)
		}
		if err := submitter.Submit(t.Context(), req); err != nil {
			t.Fatalf("second submit: %v", err)
		}

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if fake.callCount() >= 1 {
				time.Sleep(500 * time.Millisecond) // let any second delivery arrive
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		extCancel()
		_ = ext.Stop()

		is := is.New(t)
		is.Equal(fake.callCount(), 1)
	})

	// Sub-test B: retry after Nak (consumer crash simulation).
	// When the processor returns an error, the extension Naks the message, causing
	// JetStream to redeliver it. The processor must be called a second time and succeed.
	t.Run("retry_after_nak", func(t *testing.T) {
		client, cleanup := setupScannerNATSClient(t)
		t.Cleanup(cleanup)

		fake := &fakeScanProcessor{failFirst: true}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		ext := scanner.NewNATSExtension(client, fake, "ocidex", logger, nil, 5*time.Minute)

		extCtx, extCancel := context.WithCancel(t.Context())
		t.Cleanup(extCancel)
		if err := ext.Start(extCtx); err != nil {
			t.Fatalf("start extension: %v", err)
		}

		submitter := scanner.NewNATSSubmitter(client, "ocidex", nil)
		req := scanner.ScanRequest{
			RegistryURL: "registry.example.com",
			Repository:  "library/nginx",
			Digest:      "sha256:def456retry",
			RegistryID:  "00000000-0000-0000-0000-000000000002",
		}

		if err := submitter.Submit(t.Context(), req); err != nil {
			t.Fatalf("submit: %v", err)
		}

		// Wait for two calls: first fails (Nak), second succeeds after JetStream redelivery.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if fake.callCount() >= 2 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}

		extCancel()
		_ = ext.Stop()

		is := is.New(t)
		is.Equal(fake.callCount(), 2)
	})
}
