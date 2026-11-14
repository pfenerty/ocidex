---
title: Monitoring
description: Health checks, Prometheus metrics, suggested alerts and tracing.
sidebar:
  order: 9
---

## Health checks

| Endpoint | Process | What it checks |
| --- | --- | --- |
| `GET /health` (port 8080) | API | The process is up. |
| `GET /ready` (port 8080) | API | The database answers. |
| `GET /healthz` (port 9090) | Workers, agent | The process is up. |
| `GET /readyz` (port 9090) | Workers | NATS is connected and the database answers within a second. |
| `GET /metrics` (port 9090) | Everything | Prometheus metrics. Never route it through the ingress. |

The chart wires these to the Kubernetes probes. The **Admin → System Status** page shows the job
queues by state and the database's latency.

## Metrics

Every component serves Prometheus metrics on port 9090. With the Prometheus Operator installed,
`monitoring.enabled: true` creates a PodMonitor per component (the agent chart has its own
`monitoring.enabled`). With network policies on, also list your Prometheus in
`networkPolicy.ingress.metricsFrom`.

| Series | What it tells you |
| --- | --- |
| `http_server_request_duration_seconds{http_request_method,http_route,http_response_status_code}` | API latency per route. `_count` is the request count. |
| `ocidex_jobs{queue,state}` | Queue depth: `queued` and `running` jobs per queue (`scan`, or an enricher's name). Every replica reports the same value, so aggregate with `max`. |
| `ocidex_jobs_processed_total{queue,outcome}` | Finished jobs: `success`, `retry` or `permanent_failure`. |
| `ocidex_job_duration_seconds{queue}` | Time per job. |
| `ocidex_db_pool_connections{pool,state}` | Database pool connections. |
| `ocidex_db_pool_acquire_wait_seconds_total{pool}` | Time spent waiting for a database connection. |
| `ocidex_nats_publishes_total{subject_class,outcome}` | NATS publishes. Errors mean latency, not lost work: the poll loop recovers them. |
| `ocidex_registry_tags_selected{registry}`, `ocidex_registry_tags_skipped_limit{registry}` | Each registry's last walk: tags in the window, and tags the window left out. |
| `ocidex_retention_pruned_total{class}` | SBOMs the retention sweep deleted. |
| `go_*`, `process_*` | Go runtime and process statistics. |

## Suggested alerts

```yaml
groups:
  - name: ocidex
    rules:
      # The queue grows and nothing drains it.
      - alert: OcidexQueueGrowing
        expr: |
          max by (queue) (ocidex_jobs{state="queued"}) > 0
            and max by (queue) (deriv(ocidex_jobs{state="queued"}[15m])) > 0
        for: 15m
      # Jobs are failing for good.
      - alert: OcidexJobPermanentFailures
        expr: |
          sum by (queue) (rate(ocidex_jobs_processed_total{outcome="permanent_failure"}[15m]))
            / sum by (queue) (rate(ocidex_jobs_processed_total[15m])) > 0.1
        for: 15m
      # A route is slower than the 5s at which the API starts logging slow requests.
      - alert: OcidexSlowRoute
        expr: |
          histogram_quantile(0.95,
            sum by (le, http_route) (rate(http_server_request_duration_seconds_bucket[5m]))) > 5
        for: 10m
      # Requests wait for a database connection.
      - alert: OcidexDBPoolSaturated
        expr: sum by (pool, pod) (rate(ocidex_db_pool_acquire_wait_seconds_total[5m])) > 0.5
        for: 10m
```

What to do when each fires is in [Troubleshooting](/guides/operate/troubleshooting/).

## Tracing

Tracing is off by default. Turn it on with `monitoring.otel.tracesExporter: otlp` and
`monitoring.otel.endpoint` pointing at an OpenTelemetry collector (Grafana Alloy or the
OpenTelemetry Collector, feeding Tempo or Jaeger, for example). The agent chart takes the same
`monitoring.otel` values.

- Put collector credentials (`OTEL_EXPORTER_OTLP_HEADERS`) in the Secret, never in values.
- With network policies on, list the collector in `monitoring.otel.egress`.
- `monitoring.otel.metricsExporter: prometheus,otlp` pushes metrics too.

The default sampler keeps 10% of traces, whole. One sampled upload shows its request, its queries,
the jobs it queued, and every enricher that then ran. Log lines inside a sampled span carry its
`trace_id`.
