import * as path from "path";
import { Task, scriptFromFile } from "@pfenerty/tektonic";
import { goImage, goCacheIntegration, goEnv, statusReporter } from "../../shared";
import { goBuild } from "../go-build/spec";

// tests/ provisions Postgres and NATS through testcontainers locally, which needs a
// Docker daemon the build container doesn't have. Rather than a privileged DinD
// sidecar, run the two servers as plain sidecars: they share the pod's network
// namespace, so the step reaches them on localhost, and the test helpers take a
// shared-server path when TEST_POSTGRES_URL / TEST_NATS_URL are set (see
// tests/integration_test.go). Nothing under tests/ needs Docker for anything else —
// scan_to_enrich talks to a real registry over HTTPS.
export const goIntegration = new Task({
  name: "go-integration-test",
  // goBuild, not goTest, even though running after the cheap suite would be the
  // nicer fail-fast order: `gated()` returns a Proxy, so a dependent's raw `needs`
  // reference reaches past the wrapper and the PR pipeline ends up with both the
  // gated and the ungated go-test ("duplicate task name"). Only leaf tasks can be
  // gated. go-vulncheck has the same shape for the same reason.
  needs: [goBuild],
  caches: [goCacheIntegration],
  statusReporter,
  // Bounds the pathological case: `await-sidecar-readiness` means a sidecar that
  // never reports ready blocks the step indefinitely, which would otherwise burn
  // the whole pipeline timeout.
  timeout: "30m",
  stepTemplate: {
    env: [
      ...goEnv,
      { name: "GOMAXPROCS", value: "2" },
      { name: "GOMEMLIMIT", value: "2500MiB" },
      // Connect to the admin database; each test CREATEs and DROPs its own.
      {
        name: "TEST_POSTGRES_URL",
        value: "postgres://test:test@localhost:5432/postgres?sslmode=disable",
      },
      { name: "TEST_NATS_URL", value: "nats://localhost:4222" },
    ],
  },
  sidecars: [
    {
      name: "postgres",
      // Same image the testcontainers path uses, so schema behaviour is identical.
      image: "postgres:15-alpine",
      // Explicit because Tekton does not apply stepTemplate to sidecars, so the
      // project's defaultImagePullPolicy stops at the steps. Docker Hub republishes
      // 15-alpine on every patch build.
      imagePullPolicy: "Always",
      // The project-wide runAsUser: 1024 has no /etc/passwd entry, so initdb dies in
      // getpwuid ("could not look up effective user ID"). As root the image's own
      // entrypoint chowns PGDATA and re-execs as postgres, which is the supported
      // path. Permitted here: ocidex-ci is a PSA `privileged` namespace.
      //
      // runAsNonRoot: false is load-bearing, not redundant. tektonic stamps
      // runAsNonRoot: true onto every PipelineRun's podTemplate.securityContext, and
      // the kubelet enforces that check independently of Pod Security Admission — the
      // namespace being PSA `privileged` does not exempt it. Without the container-level
      // false, the pod dies at CreateContainerConfigError ("container's runAsUser
      // breaks non-root policy"). A bare ad-hoc TaskRun has no podTemplate, so this
      // only reproduces under a real PipelineRun.
      securityContext: { runAsUser: 0, runAsNonRoot: false },
      env: [
        { name: "POSTGRES_USER", value: "test" },
        { name: "POSTGRES_PASSWORD", value: "test" },
      ],
      // PGDATA lands on the container's writable layer — Kubernetes ignores the
      // image's VOLUME directive — so this needs an ephemeral-storage limit rather
      // than a volume. That also sidesteps TaskSidecarSpec having no volumeMounts.
      computeResources: {
        requests: { cpu: "100m", memory: "256Mi" },
        limits: { cpu: "1", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      // Mandatory, not belt-and-braces: with await-sidecar-readiness on, a sidecar
      // without a probe counts as ready the moment it starts, and the step would
      // race initdb.
      readinessProbe: {
        exec: { command: ["pg_isready", "-U", "test", "-d", "postgres"] },
        initialDelaySeconds: 3,
        periodSeconds: 2,
        failureThreshold: 30,
      },
    },
    {
      name: "nats",
      image: "nats:2-alpine",
      // See the postgres sidecar: stepTemplate does not reach sidecars, and 2-alpine
      // is a floating minor tag.
      imagePullPolicy: "Always",
      // JetStream is off by default, and internal/nats.Connect hardcodes
      // FileStorage — hence -js plus a writable store dir. /tmp is 1777, so this
      // needs no securityContext override. -m 8222 exposes /healthz for the probe.
      args: ["-js", "-sd", "/tmp/js", "-m", "8222"],
      computeResources: {
        requests: { cpu: "50m", memory: "64Mi" },
        limits: { cpu: "500m", memory: "256Mi", "ephemeral-storage": "1Gi" },
      },
      readinessProbe: {
        httpGet: { path: "/healthz", port: 8222 },
        initialDelaySeconds: 2,
        periodSeconds: 2,
        failureThreshold: 30,
      },
    },
  ],
  steps: [
    {
      name: "go-integration-test",
      image: goImage,
      computeResources: {
        // Compiled test binaries land in $TMPDIR; same reasoning as go-test, with
        // more headroom since this suite links every package under test.
        limits: { cpu: "2", memory: "3Gi", "ephemeral-storage": "4Gi" },
        // Requests deliberately low. This pod is scheduled alongside go-test's (they
        // share `needs: [goBuild]` and so start together) on a node already at ~77% of
        // allocatable CPU requests; step + sidecars total 250m, which fits beside
        // go-test's 500m. The limits above are what the work actually gets to burst to.
        requests: {
          cpu: "100m",
          memory: "512Mi",
          "ephemeral-storage": "2Gi",
        },
      },
      script: scriptFromFile(path.join(__dirname, "test.nu")),
      onError: "continue",
    },
  ],
});
