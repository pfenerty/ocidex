package service

import (
	"context"
	"fmt"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/repository"
)

func (s *searchService) ListLicenses(ctx context.Context, filter LicenseFilter) (PagedResult[LicenseCount], error) {
	q := repository.New(s.db)

	rows, err := q.ListLicenses(ctx, repository.ListLicensesParams{
		SpdxID:    textOrNull(filter.SpdxID),
		Name:      textOrNull(filter.Name),
		Category:  textOrNull(filter.Category),
		UserID:    filter.Visibility.UserID,
		IsAdmin:   visAdminBool(filter.Visibility),
		RowLimit:  filter.Limit,
		RowOffset: filter.Offset,
	})
	if err != nil {
		return PagedResult[LicenseCount]{}, fmt.Errorf("listing licenses: %w", err)
	}

	var total int64
	items := make([]LicenseCount, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		spdx := textToPtr(row.SpdxID)
		items = append(items, LicenseCount{
			ID:             uuidToString(row.ID),
			SpdxID:         spdx,
			Name:           row.Name,
			URL:            textToPtr(row.Url),
			ComponentCount: row.ComponentCount,
			Category:       classifyLicense(spdx),
		})
	}

	return PagedResult[LicenseCount]{
		Data:   items,
		Total:  total,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}, nil
}

func (s *searchService) ListComponentsByLicense(ctx context.Context, licenseID pgtype.UUID, limit, offset int32, vis VisibilityFilter) (PagedResult[ComponentSummary], error) {
	q := repository.New(s.db)

	rows, err := q.ListComponentsByLicense(ctx, repository.ListComponentsByLicenseParams{
		LicenseID: licenseID,
		UserID:    vis.UserID,
		IsAdmin:   visAdminBool(vis),
		RowLimit:  limit,
		RowOffset: offset,
	})
	if err != nil {
		return PagedResult[ComponentSummary]{}, fmt.Errorf("listing components by license: %w", err)
	}

	var total int64
	items := make([]ComponentSummary, 0, len(rows))
	for _, row := range rows {
		total = row.TotalCount
		items = append(items, toComponentSummary(row.ID, row.SbomID, pgtype.Text{}, row.Type, row.Name, row.GroupName, row.Version, row.Purl))
	}

	return PagedResult[ComponentSummary]{
		Data:   items,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}, nil
}

// classifyLicense returns a compliance category based on SPDX ID.
// The copyleft/weak-copyleft classification lists must be maintained manually;
// SPDX does not encode these legal categories. go-spdx is used only to validate
// that the ID is a known SPDX identifier before classifying.
func classifyLicense(spdxID *string) string {
	if spdxID == nil {
		return "uncategorized"
	}
	id := *spdxID
	// Reject unrecognized or malformed SPDX IDs before classification.
	if valid, _ := spdxexp.ValidateLicenses([]string{id}); !valid {
		return "uncategorized"
	}
	// Copyleft
	copyleft := []string{
		"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
		"GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
		"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
		"SSPL-1.0", "EUPL-1.2",
	}
	for _, c := range copyleft {
		if id == c {
			return "copyleft"
		}
	}
	// Weak copyleft
	weakCopyleft := []string{
		"LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
		"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
		"LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
		"MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
	}
	for _, c := range weakCopyleft {
		if id == c {
			return "weak-copyleft"
		}
	}
	// Everything else with an SPDX ID is considered permissive
	return "permissive"
}
