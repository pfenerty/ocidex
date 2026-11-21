package config

import (
	"log/slog"
	"os"
)

// DeprecatedSetting is an env var that still parses but no longer does
// anything, kept so a deployment that sets it keeps starting (ADR-052: a
// deprecated name keeps working for at least one minor release).
type DeprecatedSetting struct {
	Name    string
	Instead string
	Removal string
}

// deprecatedSettings is the list WarnDeprecated checks. Removing an entry's
// variable is a breaking change, so it waits for the release named in Removal.
var deprecatedSettings = []DeprecatedSetting{
	{
		Name:    "ENRICHMENT_WORKERS",
		Instead: "ENRICHMENT_MAX_CONCURRENCY on each enricher worker; this value is only reported on the admin Status page",
		Removal: "2.0",
	},
	{
		Name:    "ENRICHMENT_QUEUE_SIZE",
		Instead: "nothing: the queue is the enrichment_jobs table, which has no depth limit",
		Removal: "2.0",
	},
}

// DeprecatedSet returns the deprecated settings present in the environment,
// as reported by lookup (os.LookupEnv in production).
func DeprecatedSet(lookup func(string) (string, bool)) []DeprecatedSetting {
	var set []DeprecatedSetting
	for _, d := range deprecatedSettings {
		if _, ok := lookup(d.Name); ok {
			set = append(set, d)
		}
	}
	return set
}

// WarnDeprecated logs one warning per deprecated setting that is explicitly
// set. Call it after the process has installed its logger.
func WarnDeprecated() {
	for _, d := range DeprecatedSet(os.LookupEnv) {
		slog.Warn("deprecated setting is set and has no effect",
			"setting", d.Name, "instead", d.Instead, "removal", d.Removal)
	}
}
