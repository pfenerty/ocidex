package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// resolveIngestSource resolves the `source` query parameter to a source the
// caller may write to, returning the huma error the handler should surface.
//
// Accepted forms are a source UUID and `<namespace>/<name>`. A bare name is
// deliberately not accepted: source names are unique per namespace, not
// globally (ADR-039), so resolving one means guessing which of the caller's
// namespaces was meant — and a push that worked would start failing the day a
// second namespace gained a source of the same name. Qualified references are
// stable.
//
// An unresolvable source is a 400 rather than a 404: the request named
// something that does not exist, the endpoint exists fine. Naming a source in a
// namespace the caller cannot ingest into is a 403, whether or not they can read
// it.
func (h *Handler) resolveIngestSource(ctx context.Context, ref string) (service.Source, error) {
	if ref == "" {
		return service.Source{}, huma.Error400BadRequest(
			"source is required: pass ?source=<uuid> or ?source=<namespace>/<name>")
	}

	var (
		src service.Source
		err error
	)
	if nsName, srcName, qualified := strings.Cut(ref, "/"); qualified {
		var ns service.Namespace
		if ns, err = h.namespaceService.GetByName(ctx, nsName); err == nil {
			src, err = h.sourceService.GetByName(ctx, ns.ID, srcName)
		}
	} else if _, perr := parseUUID(ref); perr != nil {
		return service.Source{}, huma.Error400BadRequest(fmt.Sprintf(
			"source %q is neither a UUID nor a <namespace>/<name> reference", ref))
	} else {
		src, err = h.sourceService.Get(ctx, ref)
	}
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return service.Source{}, huma.Error400BadRequest(fmt.Sprintf("source %q not found", ref))
		}
		return service.Source{}, mapServiceError(err)
	}

	ns, err := h.namespaceService.Get(ctx, src.NamespaceID)
	if err != nil {
		return service.Source{}, mapServiceError(err)
	}
	if user, ok := UserFromContext(ctx); ok && !can(user, ns.ID, authz.CapIngest) {
		return service.Source{}, huma.Error403Forbidden(
			"cannot ingest into namespace " + ns.Name + ": no ingest capability there")
	}
	return src, nil
}

// IngestSBOM accepts a CycloneDX JSON SBOM, validates it, and persists it.
func (h *Handler) IngestSBOM(ctx context.Context, input *IngestSBOMInput) (*IngestSBOMOutput, error) {
	src, err := h.resolveIngestSource(ctx, input.Source)
	if err != nil {
		return nil, err
	}
	sourceID, err := parseUUID(src.ID)
	if err != nil {
		return nil, err
	}
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(input.RawBody), cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, huma.Error400BadRequest("invalid CycloneDX JSON: " + err.Error())
	}

	if details := validateBOM(bom); len(details) > 0 {
		return nil, huma.Error422UnprocessableEntity("validation failed", details...)
	}

	sbomID, err := h.sbomService.Ingest(ctx, bom, input.RawBody, service.IngestParams{
		Version:      input.Version,
		Architecture: input.Architecture,
		BuildDate:    input.BuildDate,
		SourceID:     sourceID,
		SubjectType:  input.SubjectType,
		SubjectName:  input.SubjectName,
		SubjectGroup: input.SubjectGroup,
		SubjectPurl:  input.SubjectPurl,
		Digest:       input.Digest,
	})
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
