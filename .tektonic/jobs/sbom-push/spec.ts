import * as path from "path";
import { Task, nu, scriptFromFile } from "@pfenerty/tektonic";
import {
  goImage,
  syftImage,
  goEnv,
  goCacheVulncheck,
  reportOnlyStatusReporter,
  sourceBranchParam,
} from "../../shared";
import { goBuild } from "../go-build/spec";
import { goSetup } from "../../script-lib";

// The binaries OCIDex ships — one image each in docker/Dockerfile, so one uploaded
// SBOM each. ocidex-cli is also the tool doing the pushing, but since ocidex-5dw it
// ships an image of its own, so it is a subject here like the rest.
const shippedBinaries = [
  "ocidex",
  "scanner-worker",
  "enrichment-worker",
  "oci-metadata-worker",
  "git-worker",
  "user-enricher-worker",
  "provenance-worker",
  "vuln-worker",
  "operator",
  "ocidex-cli",
];

const nuList = (xs: string[]) => `[${xs.map((x) => `"${x}"`).join(" ")}]`;

// OCIDex cataloguing its own binaries and pushing them to itself (ocidex-0gp.5).
//
// Each binary is catalogued on its own rather than as `syft dir:.sbom-bins`: a
// directory scan produces one BOM whose metadata.component is the scratch directory,
// which is precisely the unidentifiable subject the declared-subject parameters were
// added to fix. Per-binary `syft file:` scans let the go-binary cataloger read the
// linker-embedded module versions — one version per module, what actually ships —
// instead of go.sum's every-version-ever set.
//
// Report-only, and deliberately so: this is dogfooding, not a release gate. An OCIDex
// that is down, unreachable, or missing the API key must not fail a tag pipeline that
// has already built and published ten images.
export const sbomPush = new Task({
  name: "sbom-push",
  params: [sourceBranchParam],
  statusReporter: reportOnlyStatusReporter,
  // Ordered after go-build for the same reason govulncheck-scan is: goEnv points
  // GOMODCACHE/GOCACHE into the shared source workspace, and a cache restore starts by
  // rm -rf'ing them. skipRestoreIfPathsExist removes that destructive step, but only
  // `needs` guarantees the paths are already populated when this task starts.
  needs: [goBuild],
  caches: [goCacheVulncheck],
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "build-binaries",
      image: goImage,
      // Requests are deliberately far below the limits. Kubernetes schedules on the
      // *sum* of a pod's container requests, but Tekton steps run one at a time, so
      // every milli requested here is held for the whole task and counted again for
      // each of the other five steps. This task has twice the step count of any other
      // in the pipeline, and on a cluster with one untainted worker the honest
      // per-step numbers added up to more CPU than the node had free — the pod pended
      // until the task timed out, which then skipped the remaining image builds.
      // Limits still let the build burst to 2 CPUs when the node is idle.
      computeResources: {
        limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "250m", memory: "1Gi", "ephemeral-storage": "2Gi" },
      },
      script: nu`
${goSetup}
mkdir .sbom-bins
for b in ${nuList(shippedBinaries)} {
  log $"Building ($b)"
  ^go build -o $".sbom-bins/($b)" $"./cmd/($b)"
}
# Recorded here rather than assumed at push time: these are native builds, so the
# architecture is whatever the CI node happens to be, and only this step knows it.
^go env GOARCH | str trim | save -f .sbom-bins/.goarch
log $"OK: binaries built for (open .sbom-bins/.goarch | str trim)"
`,
      onError: "continue",
    },

    {
      name: "syft-catalog",
      image: syftImage,
      computeResources: {
        limits: { cpu: "1", memory: "1Gi" },
        requests: { cpu: "50m", memory: "256Mi" },
      },
      // CycloneDX rather than syft's native JSON: OCIDex ingests CycloneDX only.
      script: nu`
mkdir .sbom-out
for b in ${nuList(shippedBinaries)} {
  log $"Cataloging ($b)"
  ^syft $"file:.sbom-bins/($b)" -o $"cyclonedx-json=.sbom-out/($b).cdx.json"
}
log "OK: SBOMs written to .sbom-out"
`,
      onError: "continue",
    },

    {
      name: "push-sboms",
      image: goImage,
      computeResources: {
        limits: { cpu: "1", memory: "512Mi" },
        requests: { cpu: "50m", memory: "128Mi" },
      },
      env: [
        {
          name: "OCIDEX_URL",
          value: "http://ocidex-dev-api.ocidex-dev.svc.cluster.local",
        },
        {
          // optional so a cluster without the secret gets an empty key and the
          // skip path below, rather than a CreateContainerConfigError that would
          // fail the pod before any step runs.
          name: "OCIDEX_API_KEY",
          valueFrom: {
            secretKeyRef: { name: "ocidex-api-key", key: "key", optional: true },
          },
        },
        { name: "OCIDEX_SOURCE", value: "ocidex/ci" },
        { name: "OCIDEX_BINARIES", value: shippedBinaries.join(" ") },
      ],
      script: scriptFromFile(path.join(__dirname, "push-sboms.nu")),
      onError: "continue",
    },
  ],
});
