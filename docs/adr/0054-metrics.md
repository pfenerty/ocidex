---
status: "proposed"
date: 2026-10-20
decision-makers: Patrick Fenerty
---

# Metrics: OpenTelemetry instruments, scraped from a private port, bounded attributes

## Context and Problem Statement

OCIDex has no metrics of its own. The operator exposes controller-runtime's metrics on `:8080`.
The workers bind a health server on `:9090` (`internal/health`), which the chart already calls the
"health/metrics port", but it serves only `/healthz` and `/readyz`. The API serves `/health` and
`/ready` on its public port and nothing else. Operators of a 1.0 install need to see request
latency, queue depth, job failures, DB pool pressure and registry walk results without reading
logs. Tracing is planned next.

Which metrics library should OCIDex use, where are metrics served, and what rules keep the series
names and attribute sets stable and cheap?

## Decision Drivers

* Tracing is coming. Metrics and traces should share one SDK, one resource description and one
  export configuration, and a slow request in a histogram should lead to its trace.
* Metrics must never be reachable through the public ingress. `/metrics` names routes, queues and
  registry IDs.
* Kubernetes installs scrape. A small self-hosted install has a Prometheus-compatible scraper and
  no collector, so pull must work without one.
* Dependency weight. CLAUDE.md prefers small, idiomatic libraries.
* Cardinality must stay bounded whatever users do. An attribute must never grow with users, SBOMs,
  digests or request paths.

## Considered Options

* OpenTelemetry metrics SDK, Prometheus exporter for pull, OTLP for push
* Prometheus `client_golang`, pull, `/metrics`
* OpenTelemetry metrics SDK, OTLP push only

## Decision Outcome

Chosen option: "OpenTelemetry metrics SDK, Prometheus exporter for pull, OTLP for push". The
instrumentation code is written once against the vendor-neutral OpenTelemetry API, and tracing
(a later ADR) reuses the same SDK, resource and exporter configuration. Pull through `/metrics`
keeps working for installs without a collector.

The cost is small. `go.opentelemetry.io/otel`, `otel/metric`, `otel/sdk`, `otel/sdk/metric` and
`otel/trace` are already in the module graph at v1.47.0, indirect through k8s and cloud SDKs. Two
modules are new: `go.opentelemetry.io/otel/exporters/prometheus` and
`go.opentelemetry.io/contrib/instrumentation/runtime`. The Prometheus exporter is built on
`client_golang`, which is also already present (v1.24.1).

### Rule M1: one MeterProvider per binary, built in `internal/metrics`

`internal/metrics` builds the binary's `sdkmetric.MeterProvider` and returns it with an
`http.Handler` for `/metrics`:

* A resource with `service.name` (the binary: `ocidex-api`, `ocidex-scanner-worker`, ...),
  `service.version` (the build version) and the standard `OTEL_RESOURCE_ATTRIBUTES` overrides.
* A Prometheus exporter registered on a private `prometheus.Registry`, not
  `prometheus.DefaultRegisterer`, so a dependency that registers globally cannot add series OCIDex
  never chose. The exporter drops the `otel_scope_*` labels. It keeps `target_info`, which carries
  the resource.
* Go runtime metrics from `contrib/instrumentation/runtime`, and Prometheus's process collector
  (`process_*`) on the same registry. OpenTelemetry Go has no process instrumentation, so this is
  the one place OCIDex code calls `client_golang` directly.
* An OTLP metric reader when `OTEL_METRICS_EXPORTER` includes `otlp`, configured by the standard
  `OTEL_EXPORTER_OTLP_*` variables. It is added with the tracing work, which brings the OTLP
  exporter modules in anyway. Until then only `prometheus` (the default) is accepted.

Packages receive a `metric.MeterProvider` through their constructors, the same way the service
layer receives its dependencies, and create their instruments from it. Code never calls
`otel.GetMeterProvider()`. Tests pass a provider with a `ManualReader` and read the data points
back, or pass `noop.NewMeterProvider()` when they do not care.

The operator keeps controller-runtime's Prometheus registry. Its OCIDex instruments go through the
same `internal/metrics` setup with the exporter registered on `ctrlmetrics.Registry`, so one
endpoint keeps serving both sets.

### Rule M2: a private listener, never the public port

| Binary | Address | Setting | Serves |
|---|---|---|---|
| API (`cmd/ocidex`) | `:9090` | `METRICS_ADDR` (empty disables the listener) | `/metrics` |
| Workers, k8s-agent | `:9090` | existing health address | `/healthz`, `/readyz`, `/metrics` |
| Operator | `:8080` | `--metrics-bind-address` (unchanged) | controller-runtime `/metrics` |

The API's metrics server starts beside the main server and shuts down with it. Its health
endpoints stay on the public port, where probes already reach them. The workers add `/metrics` to
the health server they already run, so the chart's port and `metricsFrom` network policy cover
them unchanged. The chart exposes the metrics port on a separate Service port, which the ingress
never routes (ocidex-v590.5).

### Rule M3: names

* HTTP server metrics follow the OpenTelemetry semantic conventions, so they match what
  `otelhttp` emits once tracing instruments requests, and community dashboards read them as-is.
* Every other instrument is named `ocidex.<subsystem>.<name>`, dot-separated, with its unit set on
  the instrument in UCUM (`s`, `By`, `{job}`). The Prometheus exporter turns dots into underscores
  and appends the unit and `_total`, so `ocidex.jobs.processed` (counter, `{job}`) is scraped as
  `ocidex_jobs_processed_total`.
* Durations are histograms in seconds with explicit boundaries, set on the instrument, because the
  SDK's default boundaries assume milliseconds:
  0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30. The 5s boundary matches
  `slowRequestThreshold` (`internal/api/middleware.go`).
* Series names are not a 1.0 compatibility surface (ADR-0052). Renaming one still goes in the
  release notes.

### Rule M4: attributes are drawn from bounded sets

An attribute value must come from a set that OCIDex or an administrator controls:

| Allowed | Examples |
|---|---|
| A constant enum in code | `http.request.method`, `http.response.status_code`, `outcome`, `state`, `subject_class` |
| A route **pattern** | `/api/v1/sboms/{id}`, never `/api/v1/sboms/42` |
| An admin-created configuration row | registry ID, enricher name (queue) |

Never use as a metric attribute: a raw path or query string, a user, API key or session, an SBOM,
artifact, digest, tag or package, a team or namespace, an error message, or a remote address.
Spans may carry some of these later. The tracing ADR decides which.

A request that matches no route gets `http.route="unmatched"`, so a path scan adds one series. A
method outside the standard set becomes `_OTHER`, as the conventions specify. A series for a
deleted registry stops being reported when the registry is deleted.

### Rule M5: the initial metric set

Names are given as instruments, with the scraped Prometheus name below each.

| Instrument | Type | Attributes | Issue |
|---|---|---|---|
| `http.server.request.duration` <br> `http_server_request_duration_seconds` | histogram (s) | `http.request.method`, `http.route`, `http.response.status_code` | ocidex-v590.2 |
| `ocidex.jobs.processed` <br> `ocidex_jobs_processed_total` | counter | `queue`, `outcome` (`success`, `retry`, `permanent_failure`) | ocidex-v590.3 |
| `ocidex.job.duration` <br> `ocidex_job_duration_seconds` | histogram (s) | `queue` | ocidex-v590.3 |
| `ocidex.jobs` <br> `ocidex_jobs` | gauge | `queue`, `state` | ocidex-v590.3 |
| `ocidex.db.pool.connections` <br> `ocidex_db_pool_connections` | gauge | `state` (`acquired`, `idle`, `total`, `max`) | ocidex-v590.4 |
| `ocidex.db.pool.acquires` <br> `ocidex_db_pool_acquires_total` | counter | `outcome` (`waited`, `immediate`, `canceled`) | ocidex-v590.4 |
| `ocidex.db.pool.acquire_wait` <br> `ocidex_db_pool_acquire_wait_seconds_total` | counter (s) | none | ocidex-v590.4 |
| `ocidex.nats.publishes` <br> `ocidex_nats_publishes_total` | counter | `subject_class`, `outcome` (`ok`, `duplicate`, `error`) | ocidex-v590.4 |
| `ocidex.registry.tags.selected` <br> `ocidex_registry_tags_selected` | gauge | `registry` | ocidex-5y0r.7 |
| `ocidex.registry.tags.skipped_limit` <br> `ocidex_registry_tags_skipped_limit` | gauge | `registry` | ocidex-5y0r.7 |

The request count is the histogram's `_count` series, so there is no separate request counter.
Gauges read from a source (queue depth, pool stats, last walk) are observable instruments with a
callback, not values set on a timer. Runtime and process series come with every binary (M1).

### Consequences

* Good, because tracing adds spans to an SDK, resource and configuration that already exist, and
  histogram exemplars can point at traces once both are on.
* Good, because the same build can be scraped or can push through a collector, chosen at deploy
  time.
* Good, because HTTP metrics use the standard names, so existing dashboards and alerts work.
* Good, because metrics never share a port with public traffic.
* Good, because the attribute rules make cardinality a code-review question with a table to check
  against, not a production incident.
* Bad, because the scraped names come from the exporter's translation, not straight from code. The
  table in M5 is the reference, and a test checks the scraped names.
* Bad, because there are two registries in play. The SDK holds the instruments and a Prometheus
  registry serves them. Process metrics are the one direct `client_golang` use.
* Bad, because the API gains a second listener and a setting. A deployment that cannot open a
  second port sets `METRICS_ADDR=""` and needs OTLP push (after tracing lands) to keep metrics.

### Confirmation

* `internal/api` middleware test: requests to a matched route and to an unmatched path produce
  `http.route="/…/{id}"` and `http.route="unmatched"` data points, read with a `ManualReader`.
* `internal/metrics` test: the `/metrics` handler serves `go_goroutine_count` (or the runtime
  package's equivalent), `process_cpu_seconds_total`, `target_info`, and an `ocidex_` series under
  the name M5 lists.
* Review checks every new attribute against M4.

## Pros and Cons of the Options

### OpenTelemetry metrics SDK, Prometheus exporter for pull, OTLP for push

* Good, because metrics and tracing share one SDK and configuration.
* Good, because it supports pull and push from the same instruments.
* Good, because the SDK is already in the module graph. Two small modules are new.
* Bad, because the exporter translates names, and its options (scope labels, `target_info`) need
  setting deliberately.

### Prometheus `client_golang`

* Good, because it is already in the module graph, the operator already uses it, and series names
  are exactly what the code writes.
* Bad, because tracing would bring the OpenTelemetry SDK in anyway, leaving two instrumentation
  APIs, and exemplars would be wired by hand.
* Bad, because push needs a separate path.

### OpenTelemetry SDK, OTLP push only

* Good, because no port has to be opened.
* Bad, because every install then needs a collector, which a small self-hosted install does not
  have, and Kubernetes users already scrape.

## More Information

* Epic ocidex-v590. Children: v590.2 (listener and HTTP), v590.3 (jobs), v590.4 (DB pool and
  NATS), v590.5 (chart and alerts). Registry walk metrics: ocidex-5y0r.7.
* Versions at the time of writing: `otel` v1.47.0, `otel/exporters/prometheus` v0.69.0,
  `contrib/instrumentation/runtime` v0.72.0.
* ADR-0052 lists `/metrics` series names among what 1.0 does not freeze.
* Tracing needs its own ADR: span coverage (HTTP, jobs, NATS, DB), propagation over NATS
  headers, sampling, and which attributes spans may carry.
* Suggested alerts (queue growing for 15m, permanent failure rate, p95 latency over 5s, pool
  acquire wait) belong in `docs/OPERATIONS.md` under ocidex-v590.5.
