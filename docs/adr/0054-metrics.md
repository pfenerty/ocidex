---
status: "proposed"
date: 2026-10-20
decision-makers: Patrick Fenerty
---

# Metrics: Prometheus client_golang on a private port, ocidex_ names, bounded labels

## Context and Problem Statement

OCIDex has no metrics of its own. The operator exposes controller-runtime's metrics on `:8080`.
The workers bind a health server on `:9090` (`internal/health`), which the chart already calls the
"health/metrics port", but it serves only `/healthz` and `/readyz`. The API serves `/health` and
`/ready` on its public port and nothing else. Operators of a 1.0 install need to see request
latency, queue depth, job failures, DB pool pressure and registry walk results without reading
logs.

Which metrics library should OCIDex use, where are metrics served, and what rules keep the series
names and label sets stable and cheap?

## Decision Drivers

* Metrics must never be reachable through the public ingress. `/metrics` names routes, queues and
  registry IDs.
* Dependency weight. CLAUDE.md prefers small, idiomatic libraries.
* Fit with what already exists: controller-runtime's registry in the operator, the `:9090` port in
  the workers and the chart's `metricsFrom` network policy.
* Cardinality must stay bounded whatever users do. A label must never grow with users, SBOMs,
  digests or request paths.
* Tracing may come later, and this decision should not block it.

## Considered Options

* Prometheus `client_golang`, pull, `/metrics`
* OpenTelemetry metrics SDK with its Prometheus exporter
* OpenTelemetry metrics SDK pushing OTLP to a collector

## Decision Outcome

Chosen option: "Prometheus `client_golang`". It is already in the module graph at v1.24.1,
indirect through controller-runtime and k8s, so it adds no new modules. The operator already uses
it. Every common scraper reads its format. The OpenTelemetry SDK would add the SDK, the exporter
and their transitive modules only to produce the same `/metrics` output.

### Rule M1: one registry per binary, built in `internal/metrics`

`internal/metrics` builds a `prometheus.Registry` with the Go runtime and process collectors, and
it serves that registry. Binaries do not use `prometheus.DefaultRegisterer`. A dependency that
registers globally therefore cannot add series OCIDex never chose. Instruments are created by the
package that owns them and registered on the registry passed in at construction, the same way the
service layer receives its dependencies. Tests use a fresh registry.

The operator is the exception. It registers its OCIDex series on controller-runtime's
`metrics.Registry` so that one endpoint keeps serving both sets.

### Rule M2: a private listener, never the public port

| Binary | Address | Setting | Serves |
|---|---|---|---|
| API (`cmd/ocidex`) | `:9090` | `METRICS_ADDR` (empty disables) | `/metrics` |
| Workers, k8s-agent | `:9090` | existing health address | `/healthz`, `/readyz`, `/metrics` |
| Operator | `:8080` | `--metrics-bind-address` (unchanged) | controller-runtime `/metrics` |

The API's metrics server starts beside the main server and shuts down with it. Its health
endpoints stay on the public port, where probes already reach them. The workers add `/metrics` to
the health server they already run, so the chart's port and network policy cover them unchanged.
The chart exposes the metrics port on a separate Service port, which the ingress never routes
(ocidex-v590.5).

### Rule M3: names

* Every series starts with `ocidex_`, then the subsystem, then the quantity:
  `ocidex_<subsystem>_<name>_<unit>`.
* Base units only: `_seconds` and `_bytes`. Counters end in `_total`. A gauge that counts things
  is plural and has no suffix (`ocidex_jobs`).
* Durations are histograms with `prometheus.DefBuckets` widened to 30s:
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30. The 5s bucket matches
  `slowRequestThreshold` (`internal/api/middleware.go`).
* Series names are not a 1.0 compatibility surface (ADR-0052). Renaming one still goes in the
  release notes.

### Rule M4: labels are drawn from bounded sets

A label value must come from a set that OCIDex or an administrator controls:

| Allowed | Examples |
|---|---|
| A constant enum in code | `method`, `code`, `outcome`, `state`, `subject_class` |
| A route **pattern** | `/api/v1/sboms/{id}`, never `/api/v1/sboms/42` |
| An admin-created configuration row | registry ID, enricher name (queue) |

Never use as a label: a raw path or query string, a user, API key or session, an SBOM, artifact,
digest, tag or package, a team or namespace, an error message, or a remote address.

A request that matches no route is labelled `route="unmatched"`, so a path scan adds one series.
`code` is the numeric status code. A series for a deleted registry is removed when the registry
is deleted.

### Rule M5: the initial metric set

| Series | Type | Labels | Issue |
|---|---|---|---|
| `ocidex_http_requests_total` | counter | `method`, `route`, `code` | ocidex-v590.2 |
| `ocidex_http_request_duration_seconds` | histogram | `method`, `route` | ocidex-v590.2 |
| `ocidex_jobs_processed_total` | counter | `queue`, `outcome` (`success`, `retry`, `permanent_failure`) | ocidex-v590.3 |
| `ocidex_job_duration_seconds` | histogram | `queue` | ocidex-v590.3 |
| `ocidex_jobs` | gauge | `queue`, `state` | ocidex-v590.3 |
| `ocidex_db_pool_connections` | gauge | `state` (`acquired`, `idle`, `total`, `max`) | ocidex-v590.4 |
| `ocidex_db_pool_acquires_total` | counter | `outcome` (`waited`, `immediate`, `canceled`) | ocidex-v590.4 |
| `ocidex_db_pool_acquire_wait_seconds_total` | counter | none | ocidex-v590.4 |
| `ocidex_nats_publish_total` | counter | `subject_class`, `outcome` (`ok`, `duplicate`, `error`) | ocidex-v590.4 |
| `ocidex_registry_tags_selected` | gauge | `registry` | ocidex-5y0r.7 |
| `ocidex_registry_tags_skipped_limit` | gauge | `registry` | ocidex-5y0r.7 |

The Go runtime and process collectors (`go_*`, `process_*`) come with every registry (M1).

### Consequences

* Good, because no new modules are added, and the operator, workers and API share one library and
  one naming scheme.
* Good, because metrics never share a port with public traffic. The chart's existing
  `metricsFrom` network policy already describes who may scrape.
* Good, because the label rules make cardinality a code-review question with a table to check
  against, not a production incident.
* Bad, because the API gains a second listener and a setting. A deployment that cannot open a
  second port has to set `METRICS_ADDR=""` and loses metrics.
* Bad, because a push-only environment (OTLP collector, no scraper) needs a collector with a
  Prometheus receiver.
* Neutral, because tracing is a separate decision. The OpenTelemetry tracing SDK can be added
  later without touching metrics. Exemplars can link the two if both exist.

### Confirmation

* `internal/api` middleware test: requests to a matched route and to an unmatched path produce
  `route="/…/{id}"` and `route="unmatched"` samples, checked with
  `prometheus/testutil`.
* `internal/metrics` test: the server answers `/metrics` with `go_goroutines` and an OCIDex series
  registered on it.
* Review checks every new label against M4.

## Pros and Cons of the Options

### Prometheus `client_golang`

* Good, because it is already in the module graph and used by the operator.
* Good, because its text format is what Prometheus, VictoriaMetrics, Grafana Agent/Alloy and the
  OpenTelemetry collector's Prometheus receiver all scrape.
* Bad, because it ties instrumentation code to the Prometheus API. Moving to OTel later means
  rewriting each instrument, although the series can keep their names.

### OpenTelemetry metrics SDK with its Prometheus exporter

* Good, because the instrument API is vendor-neutral and can share a resource with future tracing.
* Bad, because it adds `go.opentelemetry.io/otel/sdk/metric` and the exporter, and the exporter
  depends on `client_golang` anyway.
* Bad, because the exporter's name translation (unit suffixes, `_total`, `target_info`) makes
  the series names less direct to control.

### OpenTelemetry SDK pushing OTLP

* Good, because no port has to be opened.
* Bad, because every install then needs a collector, which a small self-hosted install does not
  have, and Kubernetes users already scrape.

## More Information

* Epic ocidex-v590. Children: v590.2 (listener and HTTP), v590.3 (jobs), v590.4 (DB pool and
  NATS), v590.5 (chart and alerts). Registry walk metrics: ocidex-5y0r.7.
* ADR-0052 lists `/metrics` series names among what 1.0 does not freeze.
* Suggested alerts (queue growing for 15m, permanent failure rate, p95 latency over 5s, pool
  acquire wait) belong in `docs/OPERATIONS.md` under ocidex-v590.5.
