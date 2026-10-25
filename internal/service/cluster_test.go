package service

import (
	"testing"

	"github.com/matryer/is"
)

// The API spells sort keys in camelCase (ocidex-nps9.34); the allow-lists name
// SQL columns. clampSort bridges the two and still accepts the column name.
func TestClampSortAcceptsAPIKeys(t *testing.T) {
	is := is.New(t)
	got, _ := clampSort("vulnCount", "desc", WorkloadSortKeys)
	is.Equal(got, "vuln_count")
	got, _ = clampSort("k8sNamespace", "asc", WorkloadSortKeys)
	is.Equal(got, "k8s_namespace")
	got, _ = clampSort("vuln_count", "asc", WorkloadSortKeys)
	is.Equal(got, "vuln_count")
	got, _ = clampSort("bogus", "asc", WorkloadSortKeys)
	is.Equal(got, "")
}
