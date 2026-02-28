package enrichment

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pfenerty/ocidex/internal/repository"
)

// fakeEnricher is a test enricher that returns fixed data.
type fakeEnricher struct {
	name   string
	canRun bool
	output []byte
	err    error
	called int
	mu     sync.Mutex
}

func (f *fakeEnricher) Name() string { return f.name }

func (f *fakeEnricher) CanEnrich(_ SubjectRef) bool { return f.canRun }

func (f *fakeEnricher) Enrich(_ context.Context, _ SubjectRef) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called++
	return f.output, f.err
}

func (f *fakeEnricher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

// fakeStore records UpsertEnrichment and UpdateSBOMSubjectVersion calls.
type fakeStore struct {
	params         []repository.UpsertEnrichmentParams
	versionUpdates []repository.UpdateSBOMSubjectVersionParams
	mu             sync.Mutex
}

func (s *fakeStore) UpsertEnrichment(_ context.Context, arg repository.UpsertEnrichmentParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = append(s.params, arg)
	return nil
}

func (s *fakeStore) UpdateSBOMSubjectVersion(_ context.Context, arg repository.UpdateSBOMSubjectVersionParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versionUpdates = append(s.versionUpdates, arg)
	return nil
}

func (s *fakeStore) results() []repository.UpsertEnrichmentParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.UpsertEnrichmentParams, len(s.params))
	copy(out, s.params)
	return out
}

func (s *fakeStore) versionResults() []repository.UpdateSBOMSubjectVersionParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.UpdateSBOMSubjectVersionParams, len(s.versionUpdates))
	copy(out, s.versionUpdates)
	return out
}

func TestDispatcher_SubmitWithResult(t *testing.T) {
	store := &fakeStore{}
	d := NewDispatcher(store, nil, WithWorkers(1), WithQueueSize(1))

	ref := SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		ArtifactName: "docker.io/alpine",
	}

	// First submit should succeed.
	if !d.SubmitWithResult(ref) {
		t.Fatal("expected SubmitWithResult to return true on empty queue")
	}
	// Queue is now full (size 1); second should return false.
	if d.SubmitWithResult(ref) {
		t.Fatal("expected SubmitWithResult to return false on full queue")
	}
}

func TestDispatcher_SubmitAndProcess(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"arch": "amd64"})
	enricher := &fakeEnricher{name: "test-enricher", canRun: true, output: data}
	store := &fakeStore{}

	d := NewDispatcher(store, []Enricher{enricher}, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	ref := SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
		ArtifactType: "container",
		ArtifactName: "docker.io/alpine",
		Digest:       "sha256:abc123",
	}

	d.Submit(ref)

	// Give worker time to process.
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if enricher.callCount() != 1 {
		t.Fatalf("expected enricher called once, got %d", enricher.callCount())
	}

	results := store.results()
	if len(results) != 1 {
		t.Fatalf("expected 1 stored result, got %d", len(results))
	}
	if results[0].Status != "success" {
		t.Errorf("expected status 'success', got %q", results[0].Status)
	}
	if string(results[0].Data) != string(data) {
		t.Errorf("expected data %q, got %q", data, results[0].Data)
	}
}

func TestDispatcher_CanEnrichFiltering(t *testing.T) {
	skipped := &fakeEnricher{name: "skipped", canRun: false}
	active := &fakeEnricher{name: "active", canRun: true, output: []byte(`{}`)}
	store := &fakeStore{}

	d := NewDispatcher(store, []Enricher{skipped, active}, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	d.Submit(SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		ArtifactType: "library",
		ArtifactName: "some-lib",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if skipped.callCount() != 0 {
		t.Errorf("skipped enricher should not have been called, got %d", skipped.callCount())
	}
	if active.callCount() != 1 {
		t.Errorf("active enricher should have been called once, got %d", active.callCount())
	}
}

func TestDispatcher_ErrorRecording(t *testing.T) {
	enricher := &fakeEnricher{
		name:   "failing",
		canRun: true,
		err:    context.DeadlineExceeded,
	}
	store := &fakeStore{}

	d := NewDispatcher(store, []Enricher{enricher}, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	d.Submit(SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{1}, Valid: true},
		ArtifactType: "container",
		ArtifactName: "docker.io/alpine",
		Digest:       "sha256:abc",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	results := store.results()
	if len(results) != 1 {
		t.Fatalf("expected 1 stored result, got %d", len(results))
	}
	if results[0].Status != "error" {
		t.Errorf("expected status 'error', got %q", results[0].Status)
	}
	if !results[0].ErrorMessage.Valid {
		t.Error("expected error message to be set")
	}
}

func TestDispatcher_OCIVersionPromotion(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"imageVersion": "1.41.5", "arch": "amd64"})
	enricher := &fakeEnricher{name: "oci-metadata", canRun: true, output: data}
	store := &fakeStore{}

	d := NewDispatcher(store, []Enricher{enricher}, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	sbomID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	d.Submit(SubjectRef{
		SBOMId:       sbomID,
		ArtifactType: "container",
		ArtifactName: "docker.io/myapp",
		Digest:       "sha256:def456",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	updates := store.versionResults()
	if len(updates) != 1 {
		t.Fatalf("expected 1 subject_version update, got %d", len(updates))
	}
	if updates[0].ID != sbomID {
		t.Errorf("expected sbom ID %v, got %v", sbomID, updates[0].ID)
	}
	if !updates[0].SubjectVersion.Valid || updates[0].SubjectVersion.String != "1.41.5" {
		t.Errorf("expected subject_version '1.41.5', got %v", updates[0].SubjectVersion)
	}
}

func TestDispatcher_OCIVersionPromotion_SkipsNonOCI(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"imageVersion": "1.0.0"})
	enricher := &fakeEnricher{name: "other-enricher", canRun: true, output: data}
	store := &fakeStore{}

	d := NewDispatcher(store, []Enricher{enricher}, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	d.Submit(SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{4}, Valid: true},
		ArtifactType: "container",
		ArtifactName: "docker.io/myapp",
		Digest:       "sha256:ghi789",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if updates := store.versionResults(); len(updates) != 0 {
		t.Errorf("expected no subject_version updates for non-OCI enricher, got %d", len(updates))
	}
}
