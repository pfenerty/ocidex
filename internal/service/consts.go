package service

// OS package-manager purl types. These are matched against the type segment of
// a purl (pkg:deb/..., pkg:apk/...) and are load-bearing in three unrelated
// places: the flavor axis (ADR-020), Debian-style version comparison in
// changelog.go, and syft source-package extraction in sbom.go.
const (
	purlTypeDeb = "deb"
	purlTypeRPM = "rpm"
	purlTypeAPK = "apk"
)

// Sort vocabulary shared by the search services. These reach the repository
// layer as ORDER BY fragments, so a value outside this set silently falls back
// to a default rather than erroring.
const (
	sortAsc    = "asc"
	sortDesc   = "desc"
	sortByName = "name"

	// sortBySeverity is both a sortable column and the default ranking for
	// every vulnerability list — the catalog's and the cluster's.
	sortBySeverity = "severity"
)
