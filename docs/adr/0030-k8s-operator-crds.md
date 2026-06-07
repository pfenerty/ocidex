# ADR-030: K8s Operator CRD Schema Design

**Status:** Accepted  
**Date:** 2026-06-06  
**Epic:** ocidex-01v — 1.3 K8s Operator + CRDs

---

## Context

The OCIDex K8s operator (`cmd/operator/`) needs three Custom Resource Definitions to make OCIDex registry management declarative inside a Kubernetes cluster. Before any kubebuilder scaffolding or controller code is written, the CRD schemas and reconcile contracts must be locked down so that all three controllers can be implemented consistently.

The operator uses `pkg/client` (ADR-028, ocidex-3nu) to call the OCIDex API. All reconcilers program to the `client.Client` interface; `FakeClient` is used in controller tests.

## CRD Identity

- **API group:** `ocidex.io/v1alpha1`
- **Kinds:** `OCIRegistry`, `ScanRequest`, `APIKey`
- **Scope:** all three are namespace-scoped — simpler RBAC, aligns with per-namespace multi-tenancy

## OCIRegistry

Declaratively registers an OCI registry with OCIDex. The controller calls `CreateRegistry` / `UpdateRegistry` / `DeleteRegistry` and stores the resulting OCIDex UUID in status.

### Spec

Maps to `client.CreateRegistryInputBody` / `UpdateRegistryInputBody`:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `url` | string | yes | Registry address (e.g. `zot:5000`) |
| `name` | string | yes | Human-readable label |
| `type` | enum | yes | `docker`, `generic`, `ghcr`, `harbor`, `zot` |
| `visibility` | enum | no | `public` \| `private`; default `private` |
| `insecure` | bool | no | Allow HTTP; default `false` |
| `scanMode` | enum | no | `poll` \| `webhook` \| `both`; default `poll` |
| `pollIntervalMinutes` | int64 | no | Minutes between polls |
| `repositories` | []string | no | Explicit repository list; bypasses catalog discovery |
| `repositoryPatterns` | []string | no | Glob patterns for repositories |
| `tagPatterns` | []string | no | Glob patterns or `semver` for tags |
| `includeUntagged` | bool | no | Ingest untagged manifests (zot/harbor/ghcr only) |
| `authSecretRef` | LocalObjectReference | no | Secret containing `username` and `token` keys |

Credentials are read from the referenced Secret at reconcile time and passed to the API as plaintext. They are **never** stored in the CRD spec or status.

### Status

```go
type OCIRegistryStatus struct {
    RegistryID string             `json:"registryID,omitempty"`
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

Condition type: `Ready`
- `True` — registry exists in OCIDex and spec is in sync
- `False` — last API call failed; `message` carries the error

### Reconcile Contract

1. **Create**: `status.registryID` empty → call `CreateRegistry` → persist returned UUID in `status.registryID`; set `Ready=True`
2. **Update**: `status.registryID` set → call `GetRegistry`; if `ErrNotFound` treat as create; else call `UpdateRegistry` if spec generation changed
3. **Delete**: finalizer `ocidex.io/registry-protection` → call `DeleteRegistry` → remove finalizer
4. Idempotent: re-queuing after a transient error re-runs step 2; `GetRegistry` → `UpdateRegistry` is safe

## ScanRequest

One-shot trigger: creates a scan job in OCIDex for the referenced registry.

### Design Decision: Fire-and-Forget

`client.ScanRegistry` returns `ScanRegistryOutputBody{Message string}` — it does **not** return a job ID. There is no way to track the resulting job through the SDK without a separate list-and-match heuristic. Therefore `ScanRequest` is a dispatch-only object: it transitions to a terminal `Dispatched` state once the API call succeeds and does not attempt job tracking.

Future work: extend `ScanRegistryOutputBody` to include `job_id` (or a new `POST /registries/{id}/scans` endpoint that returns the job UUID), at which point `ScanRequest` can be upgraded to poll `GetJob` until terminal.

### Spec

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `registryRef` | LocalObjectReference | yes | Name of an `OCIRegistry` CR in the same namespace |
| `repository` | string | no | Narrow scan to this repository |
| `tag` | string | no | Narrow scan to this tag |
| `digest` | string | no | Narrow scan to this digest |

### Status

```go
type ScanRequestStatus struct {
    Phase      string             `json:"phase,omitempty"`
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

Phase values: `""` → `Pending` → `Dispatched` | `Failed`

Condition type: `Dispatched`
- `True` — `ScanRegistry` API call succeeded
- `False` — API call failed; `message` carries the error

### Reconcile Contract

1. If `status.phase` is `Dispatched` or `Failed` → no-op (prevents re-firing on re-queues)
2. Look up referenced `OCIRegistry` CR; if `status.registryID` is empty → set `phase=Pending`, requeue with exponential backoff
3. Call `client.ScanRegistry(ctx, registryID)` → set `phase=Dispatched`, `Dispatched=True`; do not requeue
4. On API error → set `phase=Failed`, `Dispatched=False` with error message; do not requeue (operator-controlled retry via re-create)

`ScanRequest` has **no finalizer** — it is a trigger, not a managed resource. Deleting the CR does not cancel the scan.

## APIKey

Declaratively provisions an OCIDex API key and writes the plaintext key into a Kubernetes Secret.

### Spec

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Human-readable label for the key |
| `scope` | string | no | `read` \| `read-write`; default `read` |
| `secretRef` | LocalObjectReference | yes | Name of the Secret to create/update with the key |

The Secret is created in the same namespace as the `APIKey` CR. The key is stored under the `api-key` data key.

### Status

```go
type APIKeyStatus struct {
    KeyID      string             `json:"keyID,omitempty"`
    Prefix     string             `json:"prefix,omitempty"`
    Conditions []metav1.Condition `json:"conditions,omitempty"`
}
```

`prefix` is the first 12 characters of the key — safe to surface for identification without exposing the full credential.

Condition type: `Ready`
- `True` — key exists in OCIDex, Secret is up to date
- `False` — last API call failed

### Reconcile Contract

1. **Create**: `status.keyID` empty → call `CreateAPIKey` → write plaintext to `secretRef` Secret (`api-key` key) → persist `keyID` and `prefix` in status; set `Ready=True`
2. **Verify**: `status.keyID` set, spec unchanged → call `ListAPIKeys`; if key with matching ID is present → no-op
3. **Rotation**: spec changed (name or scope) → call `DeleteAPIKey(status.keyID)` → call `CreateAPIKey` with new values → update Secret; update status
4. **Re-create**: key missing from list (e.g. deleted out-of-band) → treat as step 1
5. **Delete**: finalizer `ocidex.io/apikey-protection` → call `DeleteAPIKey` → delete `secretRef` Secret → remove finalizer

Spec-change detection uses `metadata.generation` tracked in an annotation; a generation bump triggers rotation.

## Status Condition Types Summary

| CRD | Condition | Meaning |
|-----|-----------|---------|
| `OCIRegistry` | `Ready` | Registry exists and is in sync |
| `ScanRequest` | `Dispatched` | Scan request was accepted by the API |
| `APIKey` | `Ready` | Key exists and Secret is current |

All conditions use `metav1.Condition` (reason + message fields follow [KEP-1929](https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/1929-built-in-rest-resources) conventions).

## Leader Election

- Enabled; scope: operator namespace
- Election resource: `Lease` (via `coordination.k8s.io/v1`)
- Election ID: `ocidex-operator-leader`

## RBAC Requirements

**ClusterRole `ocidex-operator`** (generated by controller-gen markers):
- `ocidex.io`: `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` on `ociregistries`, `scanrequests`, `apikeys`
- `ocidex.io`: `get`, `update`, `patch` on `ociregistries/status`, `scanrequests/status`, `apikeys/status`
- `coordination.k8s.io`: `get`, `list`, `watch`, `create`, `update`, `patch` on `leases`

**Role `ocidex-operator` (operator namespace)**:
- `""` (core): `get`, `create`, `update`, `patch` on `secrets` (APIKey secretRef writes)

Generated RBAC manifests land in `config/operator/rbac/` (kubebuilder default).

## Key Files

- `docs/adr/0030-k8s-operator-crds.md` — this document
- `api/v1alpha1/` — CRD types (created in ocidex-01v.2)
- `cmd/operator/main.go` — manager setup (created in ocidex-01v.2)
- `config/operator/` — RBAC + CRD install manifests (generated in ocidex-01v.2)
- `pkg/client/client.go` — `Client` interface consumed by all reconcilers (ADR-028)
