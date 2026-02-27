package tests

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/matryer/is"
	natsc "github.com/testcontainers/testcontainers-go/modules/nats"

	"github.com/pfenerty/ocidex/internal/enrichment"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// fakeDispatchRunner records SubmitWithResult calls.
type fakeDispatchRunner struct {
	mu   sync.Mutex
	refs []enrichment.SubjectRef
}

func (f *fakeDispatchRunner) SubmitWithResult(ref enrichment.SubjectRef) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs = append(f.refs, ref)
	return true
}

func (f *fakeDispatchRunner) Run(_ context.Context) {
	// no-op for testing
}

func (f *fakeDispatchRunner) results() []enrichment.SubjectRef {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]enrichment.SubjectRef, len(f.refs))
	copy(out, f.refs)
	return out
}

func TestNATS_EnrichmentConsumer(t *testing.T) {
	requireDocker(t)

	ctx := t.Context()

	// Start NATS container with JetStream.
	// JetStream (-js) is enabled by default in the testcontainers NATS module.
	natsContainer, err := natsc.Run(ctx, "docker.io/nats:latest")
	if err != nil {
		t.Fatalf("start nats container: %v", err)
	}
	t.Cleanup(func() { _ = natsContainer.Terminate(ctx) })

	natsURL, err := natsContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("nats connection string: %v", err)
	}

	streamName := "ocidex"
	client, err := natspkg.Connect(natspkg.Config{
		URL:           natsURL,
		StreamName:    streamName,
		EventTTLHours: 1,
	})
	if err != nil {
		t.Fatalf("connect nats: %v", err)
	}
	t.Cleanup(client.Close)

	// Publish a synthetic SBOMIngested envelope directly to JetStream.
	wire := struct {
		SBOMID         string `json:"sbom_id"`
		ArtifactType   string `json:"artifact_type"`
		ArtifactName   string `json:"artifact_name"`
		Digest         string `json:"digest"`
		SubjectVersion string `json:"subject_version"`
	}{
		SBOMID:         "01234567-89ab-cdef-0123-456789abcdef",
		ArtifactType:   "container",
		ArtifactName:   "docker.io/alpine",
		Digest:         "sha256:abc123",
		SubjectVersion: "3.18",
	}
	payload, _ := json.Marshal(wire)
	env := natspkg.Envelope{
		EventType: "sbom.ingested",
		Payload:   json.RawMessage(payload),
	}
	envData, _ := json.Marshal(env)

	subject := streamName + ".sbom.ingested"
	pubCtx, pubCancel := context.WithTimeout(ctx, 5*time.Second)
	defer pubCancel()
	if _, err := client.JS.Publish(pubCtx, subject, envData); err != nil {
		t.Fatalf("publish envelope: %v", err)
	}

	// Wire up NATSExtension with fake dispatcher.
	fake := &fakeDispatchRunner{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ext := enrichment.NewNATSExtensionWithStream(client, fake, streamName, logger)

	extCtx, extCancel := context.WithCancel(ctx)
	if err := ext.Start(extCtx); err != nil {
		t.Fatalf("start nats extension: %v", err)
	}

	// Wait for the message to be processed.
	deadline := time.Now().Add(10 * time.Second)
	var got []enrichment.SubjectRef
	for time.Now().Before(deadline) {
		got = fake.results()
		if len(got) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	extCancel()
	_ = ext.Stop()

	is := is.New(t)
	is.True(len(got) == 1)
	is.Equal(got[0].ArtifactName, "docker.io/alpine")
	is.Equal(got[0].Digest, "sha256:abc123")
	is.Equal(got[0].SubjectVersion, "3.18")
	is.True(got[0].SBOMId.Valid)
}
