---
status: "accepted"
date: 2026-10-20
decision-makers: Patrick Fenerty
---

# Tracing: OpenTelemetry spans, context carried on the job row, off unless configured

## Context and Problem Statement

ADR-0054 put metrics on the OpenTelemetry SDK so tracing could share it. Metrics say that the scan
queue is slow or that `/api/v1/artifacts/{id}/contains` takes 4s. They can't say which query, which
registry call or which enricher made one request or one SBOM slow. One SBOM's life crosses three
processes: an upload or catalog walk in the API, a scan in scanner-worker, then several enrichers
that queue each other (ADR-033). The hop between processes is an outbox row plus a best-effort NATS
hint (ADR-024). A worker that misses the hint claims the row from its poll loop, so the hint alone
can't carry the trace.

What do we trace, how does a trace cross the outbox, how much is kept, and what may a span carry?

## Decision Drivers

* One trace per SBOM from ingest to the last enricher, even when a hint is lost.
* Off by default and cheap when off. A small self-hosted install has no trace backend.
* Configured the standard way (`OTEL_*` variables), so any OTLP backend works (Tempo, Jaeger,
  Honeycomb, a collector).
* Spans are sampled and inspected one at a time, so they may carry identifiers that would be
  unbounded as metric labels. They must never carry secrets.
* Must not disturb the egress guard. syft and go-containerregistry clone `http.DefaultTransport`
  through a `*http.Transport` type assertion (`internal/scanner/engine/syft.go`).

## Considered Options

* Trace context on the job row, also sent in the NATS hint headers
* Trace context in NATS headers only
* Span links only, with no parent across processes

## Decision Outcome

Chosen option: "Trace context on the job row, also sent in the NATS hint headers". The row is the
outbox's source of truth, so it is the one place every claim path reads. A job's span is then a
child of the request or job that queued it, whether the worker got there through a hint, the poll
loop or the stuck-row sweep.

### Rule T1: one SDK setup, shared with metrics

A new `internal/tracing` builds the TracerProvider on the same resource `internal/metrics` builds
for the MeterProvider (moved to a shared function). Exporters come from
`go.opentelemetry.io/contrib/exporters/autoexport`, which reads the standard variables:

| Variable | Default | Effect |
|---|---|---|
| `OTEL_TRACES_EXPORTER` | `none` | `otlp` turns tracing on. `console` prints spans for debugging. |
| `OTEL_METRICS_EXPORTER` | `prometheus` | `otlp` also pushes metrics. `prometheus` keeps `/metrics` (ADR-0054). Both may be listed. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `_PROTOCOL`, `_HEADERS` | SDK defaults | Where OTLP goes and how. |
| `OTEL_TRACES_SAMPLER`, `_ARG` | `parentbased_traceidratio`, `0.1` | See T4. |

With tracing off, the global TracerProvider is the SDK's no-op one, so a span costs a context
lookup. Packages take a `trace.TracerProvider` in their constructors, the same way they take a
MeterProvider. The W3C `traceparent` / `tracestate` propagator is set globally, because
propagation has no other home.

The chart (ocidex-v590.5's follow-up) passes these variables through to every component.

### Rule T2: what gets a span

| Where | Span | How |
|---|---|---|
| API requests | server span named `METHOD /route/pattern` | `otelhttp` handler with a no-op MeterProvider, because `RequestMetrics` already records the HTTP metric. The middleware sets the span name after routing, when chi knows the pattern. |
| Outbound HTTP: registries, git hosts, OIDC, vuln feeds | client span | `otelhttp.NewTransport` around each client's own transport. Never wrap or replace `http.DefaultTransport`. |
| Database | one span per query, named by the sqlc query name | a pgx `QueryTracer` on each pool's `ConnConfig`. The SQL text goes in `db.query.text`. Arguments never do. |
| NATS publish | producer span | in `Client.PublishMsg` / `PublishMsgAsync` (ADR-0054's wrapper), injecting context into the message headers |
| Job processing | consumer span `scan job` / `enrich <name>` around the processor | in `jobqueue.Worker.run`, parented to the context stored on the row (T3) |
| Catalog walk | internal span per registry, child spans per repository | in `scanner.WalkRegistry` |

Syft's own work shows up as one span around the scan. Instrumenting inside syft is out of scope.

### Rule T3: context crosses the outbox on the row

* `scan_jobs` and `enrichment_jobs` gain a nullable `trace_context text` column holding the W3C
  `traceparent` (plus `tracestate` when set). Whatever inserts a row writes the caller's context:
  the upload request, the catalog walk, or the enricher that queues a dependent (ADR-033).
* The NATS hint also carries context in its headers, because the publish wrapper injects it into
  every message (T2). A hint consumer still uses the row's value, since a claim always reads the
  row.
* A requeued job keeps its row's context, so every attempt of one job is a child span of the same
  parent, and retries show up as siblings.
* The catalog-walk request (`catalog.walk.requested`) is a plain JetStream message with no row,
  so its header context is the parent there.
* Upserts that hit an existing row (the idempotency keys) keep the original context, so the first
  trace that queued a job owns it.

### Rule T4: sampling

The default is parent-based, keeping 10% of new traces at the root. The ratio is configurable.
A job span follows its parent's decision, so an SBOM's trace is kept or dropped as a whole. Root
spans the system starts on its own (poller ticks, vuln refresh, rollup refresh, stuck sweep) use
the same ratio. Health and readiness probes and `/metrics` are never traced.

### Rule T5: span attributes

Spans follow the OpenTelemetry semantic conventions. On top of ADR-0054 M4's metric rules, a span
**may** carry:

* OCIDex IDs: `ocidex.sbom.id`, `ocidex.job.id`, `ocidex.registry.id`, `ocidex.namespace.id`,
  `ocidex.enricher`
* Image identity: `oci.manifest.digest`, the repository, the tag
* The authenticated user's opaque ID (`enduser.id`), never their name, email or login

A span must **never** carry:

* Credentials of any kind: registry passwords and tokens, API keys, session cookies,
  `Authorization` headers, OAuth codes, `DATA_ENCRYPTION_KEYS` material
* Request or response bodies, SBOM contents, SQL arguments
* Full URLs with query strings. `url.full` is recorded with the query removed.

`otelhttp` records no headers by default. Configuration must not change that.

### Rule T6: logs carry the trace

The slog handler adds `trace_id` and `span_id` to every record logged with a context that has a
recording span. Loki and Tempo (or any equivalent pair) can then jump between a log line and its
trace. Histograms record exemplars from sampled spans. `/metrics` serves the OpenMetrics format
when the scraper asks for it, which is the only format that carries exemplars.

### Consequences

* Good, because one SBOM is one trace across the API, scanner-worker and every enricher, through
  lost hints, poll-loop claims and retries.
* Good, because tracing costs nothing until `OTEL_TRACES_EXPORTER` is set, and then it uses the
  same configuration as metrics.
* Good, because DB spans name the sqlc query, so a slow request points at the query file.
* Bad, because the job tables gain a column and the insert queries change (a migration and
  `make generate`).
* Bad, because a job queued long ago is a child of a parent that ended long ago. Trace views show
  the queue wait as a gap, which is accurate but can make traces long.
* Bad, because three dependencies are new: `autoexport` (with the OTLP exporters), `otelhttp`
  (already indirect) and a pgx tracer. If no maintained pgx tracer fits, a small one in
  `internal/tracing` is about 60 lines.

### Confirmation

* `jobqueue` test: a job claimed by ID (hint) and one claimed by `ClaimNext` (poll) both produce a
  span whose parent is the context stored on their rows, read with an in-memory span exporter.
* Integration test: an upload's trace contains the API request span, the enqueue, and the first
  enricher's job span.
* A test fails if a span from an authenticated request carries an `Authorization`,
  `Cookie` or token-like attribute.
* `syft.go`'s `GuardDefaultTransport` test still passes, which proves `http.DefaultTransport` is
  untouched.

## Pros and Cons of the Options

### Trace context on the job row, also sent in the NATS hint headers

* Good, because every claim path reads the row, so no path loses the parent.
* Bad, because it needs a migration and one more value on each insert.

### Trace context in NATS headers only

* Good, because there is no schema change.
* Bad, because the poll loop and stuck sweep, the paths that matter when NATS is unhealthy, would
  start new traces. That is exactly when a connected trace is most useful.

### Span links only, with no parent across processes

* Good, because traces stay short.
* Bad, because most backends show links poorly, and "everything that happened to this SBOM" would
  need a search, not a single trace view.

## More Information

* ADR-0054 (metrics), ADR-024 (outbox jobs), ADR-033 (per-enricher queues and dependents).
* Follow-up issues once this is accepted: SDK and exporters (T1, T6), HTTP and outbound spans,
  DB tracer, the migration and job spans (T3), and chart passthrough of `OTEL_*`.
