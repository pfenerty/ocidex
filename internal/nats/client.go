// Package nats provides a JetStream client for optional outbound event forwarding.
package nats

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Config holds NATS connection and stream parameters.
type Config struct {
	URL           string
	StreamName    string
	EventTTLHours int
	Replicas      int
}

// Client wraps a NATS connection and JetStream context.
type Client struct {
	conn *nats.Conn
	JS   jetstream.JetStream
}

// Connect establishes a NATS connection and provisions the JetStream stream.
// The stream is created or updated idempotently, so multiple instances can
// call Connect concurrently on startup without conflict.
func Connect(cfg Config) (*Client, error) {
	nc, err := nats.Connect(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats jetstream: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	replicas := cfg.Replicas
	if replicas < 1 {
		replicas = 1
	}
	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      cfg.StreamName,
		Subjects:  []string{cfg.StreamName + ".>"},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    time.Duration(cfg.EventTTLHours) * time.Hour,
		Replicas:  replicas,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("nats stream provision: %w", err)
	}

	return &Client{conn: nc, JS: js}, nil
}

// Close drains and closes the NATS connection.
func (c *Client) Close() {
	_ = c.conn.Drain()
}
