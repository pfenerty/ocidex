package scanner

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
)

const natsPublishTimeout = 5 * time.Second

// NATSSubmitter publishes scan requests to JetStream.
// It satisfies the api.ScanSubmitter interface.
type NATSSubmitter struct {
	client     *natspkg.Client
	streamName string
}

// NewNATSSubmitter creates a NATSSubmitter backed by the given client.
func NewNATSSubmitter(client *natspkg.Client, streamName string) *NATSSubmitter {
	return &NATSSubmitter{
		client:     client,
		streamName: streamName,
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
	AuthUsername string `json:"auth_username,omitempty"`
	AuthToken    string `json:"auth_token,omitempty"`
	RegistryID   string `json:"registry_id,omitempty"`
}

// Submit synchronously publishes a scan request to JetStream and returns any publish error.
func (s *NATSSubmitter) Submit(ctx context.Context, req ScanRequest) error {
	payload, err := json.Marshal(scanRequestWire(req)) //nolint:gosec // G117: auth credentials must travel with scan requests through NATS
	if err != nil {
		return err
	}

	env := natspkg.Envelope{
		EventType:  "scan.requested",
		OccurredAt: time.Now().UTC(),
		Payload:    payload,
	}

	data, err := json.Marshal(env)
	if err != nil {
		return err
	}

	pubCtx, cancel := context.WithTimeout(ctx, natsPublishTimeout)
	defer cancel()

	subject := s.streamName + ".scan.requested"
	msg := nats.NewMsg(subject)
	msg.Header.Set("Nats-Msg-Id", req.RegistryID+"@"+req.Digest)
	msg.Data = data
	_, err = s.client.JS.PublishMsg(pubCtx, msg)
	return err
}
