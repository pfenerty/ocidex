package api_test

import (
	"context"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/scanner"
	"github.com/pfenerty/ocidex/internal/service"
)

// recordingScanSubmitter captures scan requests submitted by the webhook handler.
type recordingScanSubmitter struct {
	requests []scanner.ScanRequest
}

func (r *recordingScanSubmitter) Submit(_ context.Context, req scanner.ScanRequest) error {
	r.requests = append(r.requests, req)
	return nil
}

const webhookRegistryID = "11111111-1111-4111-8111-111111111111"

// webhookInput builds a valid, authenticated webhook request for an OCI image
// manifest push of the given reference.
func webhookInput(reference string) *api.RegistryWebhookInput {
	in := &api.RegistryWebhookInput{
		ID:            webhookRegistryID,
		Authorization: "Bearer s3cret",
	}
	in.Body.Name = "myrepo"
	in.Body.Reference = reference
	in.Body.Digest = "sha256:deadbeef"
	in.Body.MediaType = "application/vnd.oci.image.manifest.v1+json"
	return in
}

func newWebhookHandler(sub api.ScanSubmitter) *api.Handler {
	secret := "s3cret"
	regSvc := &fakeRegistryService{registry: service.Registry{
		ID:            webhookRegistryID,
		URL:           "registry.example.com",
		Enabled:       true,
		ScanMode:      "webhook",
		WebhookSecret: &secret,
	}}
	return api.NewHandler(nil, nil, nil, regSvc, nil, nil, nil, nil, nil, &fakePinger{}, sub, nil)
}

// TestHandleRegistryWebhook_SkipsCosignTags verifies that a cosign signature or
// attestation push is accepted but not queued. These carry an image manifest
// media type, so the media-type filter alone lets them through (ocidex-ptj2).
func TestHandleRegistryWebhook_SkipsCosignTags(t *testing.T) {
	const hex64 = "1111111111111111111111111111111111111111111111111111111111111111"
	cases := []struct {
		reference string
		wantScan  bool
	}{
		{"sha256-" + hex64 + ".sig", false},
		{"sha256-" + hex64 + ".att", false},
		{"sha256-" + hex64 + ".sbom", false},
		{"v1.0.0", true},
		{"latest", true},
	}

	for _, tc := range cases {
		t.Run(tc.reference, func(t *testing.T) {
			is := is.New(t)

			sub := &recordingScanSubmitter{}
			h := newWebhookHandler(sub)

			_, err := h.HandleRegistryWebhook(t.Context(), webhookInput(tc.reference))

			is.NoErr(err)
			if tc.wantScan {
				is.Equal(len(sub.requests), 1)
				is.Equal(sub.requests[0].Tag, tc.reference)
			} else {
				is.Equal(len(sub.requests), 0)
			}
		})
	}
}
