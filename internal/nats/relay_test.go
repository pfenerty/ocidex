package nats

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
)

func makeUUID(b [16]byte) pgtype.UUID {
	return pgtype.UUID{Bytes: b, Valid: true}
}

func TestUUIDToString(t *testing.T) {
	is := is.New(t)
	u := pgtype.UUID{
		Bytes: [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
		Valid: true,
	}
	got := uuidToString(u)
	is.Equal(got, "01234567-89ab-cdef-0123-456789abcdef")
}

func TestUUIDToString_Invalid(t *testing.T) {
	is := is.New(t)
	is.Equal(uuidToString(pgtype.UUID{}), "")
}

func TestSubjectMap_AllEventTypes(t *testing.T) {
	cases := []struct {
		typ     event.Type
		subject string
	}{
		{event.SBOMIngested, "sbom.ingested"},
		{event.SBOMDeleted, "sbom.deleted"},
		{event.ArtifactCreated, "artifact.created"},
		{event.ArtifactDeleted, "artifact.deleted"},
	}
	for _, tc := range cases {
		t.Run(string(tc.typ), func(t *testing.T) {
			is := is.New(t)
			got, ok := subjectMap[tc.typ]
			is.True(ok)
			is.Equal(got, tc.subject)
		})
	}
}

func TestMarshalPayload_SBOMIngested(t *testing.T) {
	is := is.New(t)
	id := makeUUID([16]byte{1})
	ev := event.Event{
		Type: event.SBOMIngested,
		Data: event.SBOMIngestedData{
			SBOMID:         id,
			ArtifactType:   "container",
			ArtifactName:   "docker.io/alpine",
			Digest:         "sha256:abc",
			SubjectVersion: "3.18",
		},
	}

	raw, err := marshalPayload(ev)
	is.NoErr(err)

	var wire sbomIngestedWire
	is.NoErr(json.Unmarshal(raw, &wire))
	is.Equal(wire.ArtifactType, "container")
	is.Equal(wire.ArtifactName, "docker.io/alpine")
	is.Equal(wire.Digest, "sha256:abc")
	is.Equal(wire.SubjectVersion, "3.18")
	// UUID should be a formatted string, not empty.
	is.True(len(wire.SBOMID) == 36)
}

func TestMarshalPayload_SBOMDeleted(t *testing.T) {
	is := is.New(t)
	id := makeUUID([16]byte{2})
	ev := event.Event{
		Type: event.SBOMDeleted,
		Data: event.SBOMDeletedData{SBOMID: id},
	}

	raw, err := marshalPayload(ev)
	is.NoErr(err)

	var wire sbomDeletedWire
	is.NoErr(json.Unmarshal(raw, &wire))
	is.True(len(wire.SBOMID) == 36)
}

func TestMarshalPayload_ArtifactDeleted(t *testing.T) {
	is := is.New(t)
	id := makeUUID([16]byte{3})
	ev := event.Event{
		Type: event.ArtifactDeleted,
		Data: event.ArtifactDeletedData{ArtifactID: id},
	}

	raw, err := marshalPayload(ev)
	is.NoErr(err)

	var wire artifactDeletedWire
	is.NoErr(json.Unmarshal(raw, &wire))
	is.True(len(wire.ArtifactID) == 36)
}

func TestMarshalPayload_UnknownType(t *testing.T) {
	// Unknown data type marshals without error (falls through to json.Marshal).
	is := is.New(t)
	ev := event.Event{Type: "unknown", Data: map[string]string{"foo": "bar"}}
	raw, err := marshalPayload(ev)
	is.NoErr(err)
	is.True(len(raw) > 0)
}
