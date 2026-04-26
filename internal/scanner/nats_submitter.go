package scanner

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	natspkg "github.com/pfenerty/ocidex/internal/nats"
	"github.com/pfenerty/ocidex/internal/service"
)

const natsPublishTimeout = 5 * time.Second

// NATSSubmitter publishes scan requests to JetStream.
// It satisfies the api.ScanSubmitter interface.
type NATSSubmitter struct {
	client     *natspkg.Client
	streamName string
	jobSvc     service.JobService // optional; nil disables job tracking
}

// NewNATSSubmitter creates a NATSSubmitter backed by the given client.
func NewNATSSubmitter(client *natspkg.Client, streamName string, jobSvc service.JobService) *NATSSubmitter {
	return &NATSSubmitter{
		client:     client,
		streamName: streamName,
		jobSvc:     jobSvc,
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
	msgID := req.RegistryID + "@" + req.Digest

	if s.jobSvc != nil {
		if _, err := s.jobSvc.Enqueue(ctx, req.RegistryID, req.Repository, req.Digest, req.Tag, msgID); err != nil {
			slog.Warn("scan_jobs: failed to enqueue job", "msg_id", msgID, "err", err)
		}
	}

	payload, err := json.Marshal(scanRequestWire{ //nolint:gosec // G117: auth credentials must travel with scan requests through NATS
		RegistryURL:  req.RegistryURL,
		Insecure:     req.Insecure,
		Repository:   req.Repository,
		Digest:       req.Digest,
		Tag:          req.Tag,
		Architecture: req.Architecture,
		BuildDate:    req.BuildDate,
		ImageVersion: req.ImageVersion,
		AuthUsername: req.AuthUsername,
		AuthToken:    req.AuthToken,
		RegistryID:   req.RegistryID,
	})
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
	msg.Header.Set("Nats-Msg-Id", msgID)
	msg.Data = data
	_, err = s.client.JS.PublishMsg(pubCtx, msg)
	return err
}
