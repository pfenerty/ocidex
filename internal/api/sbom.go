package api

import (
	"bytes"
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/danielgtaylor/huma/v2"
)

// IngestSBOM accepts a CycloneDX JSON SBOM, validates it, and persists it.
func (h *Handler) IngestSBOM(ctx context.Context, input *IngestSBOMInput) (*IngestSBOMOutput, error) {
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(input.RawBody), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, huma.Error400BadRequest("invalid CycloneDX JSON: " + err.Error())
	}

	if details := validateBOM(bom); len(details) > 0 {
		return nil, huma.Error422UnprocessableEntity("validation failed", details...)
	}

	sbomID, err := h.sbomService.Ingest(ctx, bom, input.RawBody)
	if err != nil {
		return nil, mapServiceError(err)
	}

	componentCount := 0
	if bom.Components != nil {
		componentCount = len(*bom.Components)
	}

	out := &IngestSBOMOutput{}
	out.Body.ID = fmt.Sprintf("%x-%x-%x-%x-%x", sbomID.Bytes[0:4], sbomID.Bytes[4:6], sbomID.Bytes[6:8], sbomID.Bytes[8:10], sbomID.Bytes[10:16])
	out.Body.Status = "accepted"
	out.Body.SpecVersion = bom.SpecVersion.String()
	out.Body.SerialNumber = bom.SerialNumber
	out.Body.ComponentCount = componentCount
	return out, nil
}

// DeleteSBOM removes an SBOM by ID.
func (h *Handler) DeleteSBOM(ctx context.Context, input *DeleteSBOMInput) (*struct{}, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	if err := h.sbomService.DeleteSBOM(ctx, id); err != nil {
		return nil, mapServiceError(err)
	}

	return nil, nil
}

// DeleteArtifact removes an artifact and all its SBOMs by ID.
func (h *Handler) DeleteArtifact(ctx context.Context, input *DeleteArtifactInput) (*struct{}, error) {
	id, err := parseUUID(input.ID)
	if err != nil {
		return nil, err
	}

	if err := h.sbomService.DeleteArtifact(ctx, id); err != nil {
		return nil, mapServiceError(err)
	}

	return nil, nil
}

// validateBOM checks required fields on a decoded CycloneDX BOM.
// Returns a slice of huma ErrorDetail entries (empty if valid).
func validateBOM(bom *cdx.BOM) []error {
	var details []error

	if bom.BOMFormat == "" {
		details = append(details, &huma.ErrorDetail{
			Location: "body.bomFormat",
			Message:  "required",
			Value:    bom.BOMFormat,
		})
	}

	if bom.SpecVersion.String() == "" {
		details = append(details, &huma.ErrorDetail{
			Location: "body.specVersion",
			Message:  "required",
			Value:    bom.SpecVersion.String(),
		})
	}

	if bom.Components == nil || len(*bom.Components) == 0 {
		details = append(details, &huma.ErrorDetail{
			Location: "body.components",
			Message:  "at least one component is required",
			Value:    bom.Components,
		})
	}

	return details
}
