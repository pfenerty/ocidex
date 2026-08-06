package enrichment

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

// fakeStore records UpsertEnrichment, UpdateSBOMSubjectVersion, and UpdateSBOMEnrichmentSufficient calls.
type fakeStore struct {
	params             []repository.UpsertEnrichmentParams
	versionUpdates     []repository.UpdateSBOMSubjectVersionParams
	sufficiencyUpdates []repository.UpdateSBOMEnrichmentSufficientParams
	driftInserts       []repository.InsertProvenanceDriftParams
	// priorEnrichment, if set, is returned by GetEnrichment for any call;
	// priorEnrichmentErr overrides it with an error (e.g. pgx.ErrNoRows).
	priorEnrichment    repository.Enrichment
	priorEnrichmentErr error
	mu                 sync.Mutex
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

func (s *fakeStore) UpdateSBOMEnrichmentSufficient(_ context.Context, arg repository.UpdateSBOMEnrichmentSufficientParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sufficiencyUpdates = append(s.sufficiencyUpdates, arg)
	return nil
}

func (s *fakeStore) GetEnrichment(_ context.Context, _ repository.GetEnrichmentParams) (repository.Enrichment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priorEnrichmentErr != nil {
		return repository.Enrichment{}, s.priorEnrichmentErr
	}
	return s.priorEnrichment, nil
}

func (s *fakeStore) InsertProvenanceDrift(_ context.Context, arg repository.InsertProvenanceDriftParams) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.driftInserts = append(s.driftInserts, arg)
	return nil
}

func (s *fakeStore) driftResults() []repository.InsertProvenanceDriftParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.InsertProvenanceDriftParams, len(s.driftInserts))
	copy(out, s.driftInserts)
	return out
}

func (s *fakeStore) sufficiencyResults() []repository.UpdateSBOMEnrichmentSufficientParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]repository.UpdateSBOMEnrichmentSufficientParams, len(s.sufficiencyUpdates))
	copy(out, s.sufficiencyUpdates)
	return out
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
	d := NewDispatcher(store, NewCatalog(), WithWorkers(1), WithQueueSize(1))

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

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

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

	reg := NewCatalog()
	reg.Register(skipped)
	reg.Register(active)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

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

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

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

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

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

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

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

func TestDispatcher_EnrichmentSufficiency(t *testing.T) {
	tests := []struct {
		name         string
		artifactType string
		data         map[string]string
		wantSuf      bool
	}{
		{
			name:         "both imageVersion and architecture present",
			artifactType: "container",
			data:         map[string]string{"imageVersion": "1.0.0", "architecture": "amd64"},
			wantSuf:      true,
		},
		{
			name:         "missing architecture",
			artifactType: "container",
			data:         map[string]string{"imageVersion": "1.0.0"},
			wantSuf:      false,
		},
		{
			name:         "missing imageVersion",
			artifactType: "container",
			data:         map[string]string{"architecture": "amd64"},
			wantSuf:      false,
		},
		{
			name:         "both empty",
			artifactType: "container",
			data:         map[string]string{},
			wantSuf:      false,
		},
		// Architecture is an OCI image concept (ocidex-m7vv). Requiring it of a
		// non-container is asking for a field that does not exist, which left
		// every uploaded binary permanently below the sufficiency bar and so
		// invisible in the default artifact list.
		{
			name:         "non-container needs no architecture",
			artifactType: "application",
			data:         map[string]string{"imageVersion": "0.0.0-abc1234"},
			wantSuf:      true,
		},
		{
			name:         "non-container still needs a version",
			artifactType: "library",
			data:         map[string]string{},
			wantSuf:      false,
		},
		{
			// Pre-ADR-040 rows carry no type; they were all images, so they keep
			// the stricter rule rather than being promoted by the absence of data.
			name:         "empty type is treated as a container",
			artifactType: "",
			data:         map[string]string{"imageVersion": "1.0.0"},
			wantSuf:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.data)
			enricher := &fakeEnricher{name: "oci-metadata", canRun: true, output: data}
			store := &fakeStore{}

			reg := NewCatalog()
			reg.Register(enricher)
			d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				d.Run(ctx)
				close(done)
			}()

			sbomID := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}
			d.Submit(SubjectRef{
				SBOMId:       sbomID,
				ArtifactType: tt.artifactType,
				ArtifactName: "docker.io/myapp",
				Digest:       "sha256:suf123",
			})

			time.Sleep(100 * time.Millisecond)
			cancel()
			<-done

			results := store.sufficiencyResults()
			if len(results) != 1 {
				t.Fatalf("expected 1 sufficiency update, got %d", len(results))
			}
			if results[0].ID != sbomID {
				t.Errorf("expected sbom ID %v, got %v", sbomID, results[0].ID)
			}
			if results[0].EnrichmentSufficient != tt.wantSuf {
				t.Errorf("expected enrichment_sufficient=%v, got %v", tt.wantSuf, results[0].EnrichmentSufficient)
			}
		})
	}
}

func TestDispatcher_EnrichmentSufficiency_SkipsOtherEnrichers(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"imageVersion": "1.0.0", "architecture": "amd64"})
	enricher := &fakeEnricher{name: "other-enricher", canRun: true, output: data}
	store := &fakeStore{}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	d.Submit(SubjectRef{
		SBOMId:       pgtype.UUID{Bytes: [16]byte{6}, Valid: true},
		ArtifactType: "container",
		ArtifactName: "docker.io/myapp",
		Digest:       "sha256:nonsuf",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if updates := store.sufficiencyResults(); len(updates) != 0 {
		t.Errorf("expected no sufficiency updates for non-OCI enricher, got %d", len(updates))
	}
}

func TestDispatcher_UserEnricher_TriggersSufficiency(t *testing.T) {
	data, _ := json.Marshal(map[string]string{"imageVersion": "1.0.0", "architecture": "amd64"})
	enricher := &fakeEnricher{name: "user", canRun: true, output: data}
	store := &fakeStore{}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg, WithWorkers(1), WithQueueSize(10))

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		d.Run(ctx)
		close(done)
	}()

	sbomID := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}
	d.Submit(SubjectRef{
		SBOMId:         sbomID,
		ArtifactType:   "container",
		ArtifactName:   "docker.io/myapp",
		Architecture:   "amd64",
		SubjectVersion: "1.0.0",
	})

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	results := store.sufficiencyResults()
	if len(results) != 1 {
		t.Fatalf("expected 1 sufficiency update from user enricher, got %d", len(results))
	}
	if !results[0].EnrichmentSufficient {
		t.Error("expected enrichment_sufficient=true from user enricher with arch+version")
	}
	// User enricher must NOT trigger subject_version promotion (OCI only).
	if updates := store.versionResults(); len(updates) != 0 {
		t.Errorf("expected no subject_version updates from user enricher, got %d", len(updates))
	}
}

// ---------------------------------------------------------------------------
// Provenance drift detection
// ---------------------------------------------------------------------------

func provenanceJSON(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshaling provenance fixture: %v", err)
	}
	return data
}

func TestDispatcher_ProvenanceDrift_TrustConfigChanged(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"verified": true, "signerFingerprint": "abc123"})
	newData := provenanceJSON(t, map[string]any{"verified": false, "signerFingerprint": "abc123"})
	enricher := &fakeEnricher{name: "provenance", canRun: true, output: newData}
	store := &fakeStore{priorEnrichment: repository.Enrichment{Status: "success", Data: oldData}}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{8}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	drifts := store.driftResults()
	if len(drifts) != 1 {
		t.Fatalf("expected 1 drift event, got %d", len(drifts))
	}
	if drifts[0].SbomID != sbomID {
		t.Errorf("expected sbom ID %v, got %v", sbomID, drifts[0].SbomID)
	}
	if drifts[0].PreviousStatus != "verified" || drifts[0].NewStatus != "verification_failed" {
		t.Errorf("expected verified->verification_failed, got %s->%s", drifts[0].PreviousStatus, drifts[0].NewStatus)
	}
	if drifts[0].Reason != "trust_config_changed" {
		t.Errorf("expected reason trust_config_changed (same signer, different outcome), got %s", drifts[0].Reason)
	}
}

func TestDispatcher_ProvenanceDrift_ArtifactMissing(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"verified": true, "signerFingerprint": "abc123"})
	newData := provenanceJSON(t, map[string]any{"artifactMissing": true})
	enricher := &fakeEnricher{name: "provenance", canRun: true, output: newData}
	store := &fakeStore{priorEnrichment: repository.Enrichment{Status: "success", Data: oldData}}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	drifts := store.driftResults()
	if len(drifts) != 1 {
		t.Fatalf("expected 1 drift event, got %d", len(drifts))
	}
	if drifts[0].NewStatus != "artifact_missing" || drifts[0].Reason != "artifact_missing" {
		t.Errorf("expected new_status=artifact_missing reason=artifact_missing, got %s/%s", drifts[0].NewStatus, drifts[0].Reason)
	}
}

func TestDispatcher_ProvenanceDrift_ReverificationFailedWhenSignerDiffers(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"verified": true, "signerIdentity": "https://github.com/example/repo/.*", "signerIssuer": "https://token.actions.githubusercontent.com"})
	newData := provenanceJSON(t, map[string]any{"signaturePresent": false, "attestationPresent": false})
	enricher := &fakeEnricher{name: "provenance", canRun: true, output: newData}
	store := &fakeStore{priorEnrichment: repository.Enrichment{Status: "success", Data: oldData}}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{10}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	drifts := store.driftResults()
	if len(drifts) != 1 {
		t.Fatalf("expected 1 drift event, got %d", len(drifts))
	}
	if drifts[0].Reason != "reverification_failed" {
		t.Errorf("expected reason reverification_failed (signature disappeared, no comparable signer), got %s", drifts[0].Reason)
	}
}

func TestDispatcher_ProvenanceDrift_NoRecordWhenUnchanged(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"verified": true, "signerFingerprint": "abc123"})
	newData := provenanceJSON(t, map[string]any{"verified": true, "signerFingerprint": "abc123"})
	enricher := &fakeEnricher{name: "provenance", canRun: true, output: newData}
	store := &fakeStore{priorEnrichment: repository.Enrichment{Status: "success", Data: oldData}}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{11}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift events when status is unchanged, got %d", len(drifts))
	}
}

func TestDispatcher_ProvenanceDrift_NoRecordWithoutPriorEnrichment(t *testing.T) {
	newData := provenanceJSON(t, map[string]any{"verified": false})
	enricher := &fakeEnricher{name: "provenance", canRun: true, output: newData}
	store := &fakeStore{priorEnrichmentErr: pgx.ErrNoRows} // first-ever enrichment for this SBOM

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{12}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift events on first-ever enrichment, got %d", len(drifts))
	}
}

func TestDispatcher_ProvenanceDrift_ScopedToProvenanceEnricher(t *testing.T) {
	oldData := provenanceJSON(t, map[string]any{"imageVersion": "1.0.0"})
	newData := provenanceJSON(t, map[string]any{"imageVersion": "2.0.0"})
	enricher := &fakeEnricher{name: "oci-metadata", canRun: true, output: newData}
	store := &fakeStore{priorEnrichment: repository.Enrichment{Status: "success", Data: oldData}}

	reg := NewCatalog()
	reg.Register(enricher)
	d := NewDispatcher(store, reg)

	sbomID := pgtype.UUID{Bytes: [16]byte{13}, Valid: true}
	if err := d.ProcessOne(t.Context(), SubjectRef{SBOMId: sbomID, ArtifactType: "container", ArtifactName: "docker.io/myapp"}); err != nil {
		t.Fatalf("ProcessOne: %v", err)
	}

	if drifts := store.driftResults(); len(drifts) != 0 {
		t.Errorf("expected no drift events for non-provenance enrichers, got %d", len(drifts))
	}
}
