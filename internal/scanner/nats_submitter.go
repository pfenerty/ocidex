package scanner

import (
	"encoding/json"
	"log/slog"
	"time"

	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

// NATSSubmitter publishes scan requests to JetStream.
// It satisfies the api.ScanSubmitter interface.
type NATSSubmitter struct {
	client     *natspkg.Client
	streamName string
	logger     *slog.Logger
}

// NewNATSSubmitter creates a NATSSubmitter backed by the given client.
func NewNATSSubmitter(client *natspkg.Client, logger *slog.Logger) *NATSSubmitter {
	return &NATSSubmitter{
		client:     client,
		streamName: "ocidex",
		logger:     logger,
	}
}

// scanRequestWire is the wire format for scan requests published to NATS.
type scanRequestWire struct {
	RegistryURL  string `json:"registry_url"`
	Insecure     bool   `json:"insecure"`
	Repository   string `json:"repository"`
	Digest       string `json:"digest"`
	Tag          string `json:"tag"`
	Architecture string `json:"architecture,omitempty"`
	BuildDate    string `json:"build_date,omitempty"`
	ImageVersion string `json:"image_version,omitempty"`
}

// Submit publishes a scan request to "ocidex.scan.requested".
// Best-effort: failures are logged but do not block the caller.
func (s *NATSSubmitter) Submit(req ScanRequest) {
	payload, err := json.Marshal(scanRequestWire{
		RegistryURL:  req.RegistryURL,
		Insecure:     req.Insecure,
		Repository:   req.Repository,
		Digest:       req.Digest,
		Tag:          req.Tag,
		Architecture: req.Architecture,
		BuildDate:    req.BuildDate,
		ImageVersion: req.ImageVersion,
	})
	if err != nil {
		s.logger.Error("nats submitter: marshal payload", "err", err)
		return
	}

	env := natspkg.Envelope{
		EventType:  "scan.requested",
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}

	data, err := json.Marshal(env)
	if err != nil {
		s.logger.Error("nats submitter: marshal envelope", "err", err)
		return
	}

	subject := s.streamName + ".scan.requested"
	if _, err := s.client.JS.PublishAsync(subject, data); err != nil {
		s.logger.Error("nats submitter: publish", "subject", subject, "err", err)
	}
}
