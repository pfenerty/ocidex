package enrichment

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// recordingMsg records which ack method was called.
type recordingMsg struct {
	data   []byte
	acked  bool
	nacked bool
	termed bool
}

func (m *recordingMsg) Data() []byte { return m.data }
func (m *recordingMsg) Ack() error   { m.acked = true; return nil }
func (m *recordingMsg) Nak() error   { m.nacked = true; return nil }
func (m *recordingMsg) Term() error  { m.termed = true; return nil }

func TestParseUUID(t *testing.T) {
	is := is.New(t)

	valid := "01234567-89ab-cdef-0123-456789abcdef"
	u, err := parseUUID(valid)
	is.NoErr(err)
	is.True(u.Valid)

	got := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		u.Bytes[0:4], u.Bytes[4:6], u.Bytes[6:8], u.Bytes[8:10], u.Bytes[10:16])
	is.Equal(got, valid)
}

func TestParseUUID_Invalid(t *testing.T) {
	is := is.New(t)
	_, err := parseUUID("not-a-uuid")
	is.True(err != nil)
	_, err = parseUUID("")
	is.True(err != nil)
}

func TestNATSExtension_Init_IsNoOp(t *testing.T) {
	is := is.New(t)
	e := &NATSExtension{streamName: "ocidex", logger: noopLogger()}
	err := e.Init(nil)
	is.NoErr(err)
}

func TestHandleMsg_MalformedEnvelope(t *testing.T) {
	is := is.New(t)
	store := &fakeStore{}
	d := NewDispatcher(store, NewRegistry(), WithWorkers(1), WithQueueSize(10))
	ext := &NATSExtension{dispatcher: d, streamName: "ocidex", logger: noopLogger()}

	msg := &recordingMsg{data: []byte("not json")}
	ext.handleMsg(msg)

	is.True(msg.termed)
	is.True(!msg.acked)
}

func TestHandleMsg_MalformedPayload(t *testing.T) {
	is := is.New(t)
	store := &fakeStore{}
	d := NewDispatcher(store, NewRegistry(), WithWorkers(1), WithQueueSize(10))
	ext := &NATSExtension{dispatcher: d, streamName: "ocidex", logger: noopLogger()}

	env := natspkg.Envelope{
		EventType: "sbom.ingested",
		Payload:   json.RawMessage(`"not an object"`),
	}
	data, _ := json.Marshal(env)
	msg := &recordingMsg{data: data}
	ext.handleMsg(msg)

	is.True(msg.termed)
}

func TestHandleMsg_QueueFull(t *testing.T) {
	is := is.New(t)
	store := &fakeStore{}
	d := NewDispatcher(store, NewRegistry(), WithWorkers(1), WithQueueSize(1))

	// Fill the queue so SubmitWithResult returns false.
	d.Submit(SubjectRef{SBOMId: pgtype.UUID{Bytes: [16]byte{1}, Valid: true}})

	ext := &NATSExtension{dispatcher: d, streamName: "ocidex", logger: noopLogger()}

	msg := &recordingMsg{data: makeIngestedEnvelope("01234567-89ab-cdef-0123-456789abcdef")}
	ext.handleMsg(msg)

	is.True(msg.nacked)
	is.True(!msg.acked)
}

func TestHandleMsg_Success(t *testing.T) {
	is := is.New(t)
	store := &fakeStore{}
	d := NewDispatcher(store, NewRegistry(), WithWorkers(1), WithQueueSize(10))
	ext := &NATSExtension{dispatcher: d, streamName: "ocidex", logger: noopLogger()}

	msg := &recordingMsg{data: makeIngestedEnvelope("01234567-89ab-cdef-0123-456789abcdef")}
	ext.handleMsg(msg)

	is.True(msg.acked)
	is.True(!msg.nacked)
}

func makeIngestedEnvelope(sbomID string) []byte {
	wire := struct {
		SBOMID         string `json:"sbom_id"`
		ArtifactType   string `json:"artifact_type"`
		ArtifactName   string `json:"artifact_name"`
		Digest         string `json:"digest"`
		SubjectVersion string `json:"subject_version"`
	}{
		SBOMID:       sbomID,
		ArtifactType: "container",
		ArtifactName: "docker.io/alpine",
		Digest:       "sha256:abc",
	}
	payload, _ := json.Marshal(wire)
	env := natspkg.Envelope{
		EventType: "sbom.ingested",
		Payload:   json.RawMessage(payload),
	}
	data, _ := json.Marshal(env)
	return data
}
