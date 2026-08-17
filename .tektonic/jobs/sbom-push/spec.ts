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

// The pushing is done by the ocidex-cli that build-binaries compiles below, not by
// the published ghcr.io/pfenerty/ocidex-cli image (ocidex-qzz2, reversing the image
// half of ocidex-2u7y).
//
// ocidex-2u7y ran the published `:main` for dogfooding fidelity, accepting that this
// task runs before the image-build chain and so consumes the *previous* commit's CLI
// — a newly added flag would not exist there until the following run, costing one
// degraded but self-healing run. The self-heal never happened. Kubernetes defaults
// imagePullPolicy to IfNotPresent for any tag other than `:latest`, so the kubelet
// reused the layer it first cached for `:main` and never re-pulled: run 9cl9q ran a
// build from sha-12b11d22, two builds stale, while `:main` had long since moved to
// sha-305ded74. Every push step exited 2 on `unknown flag: --version-file` for as
// long as that node kept the layer. tektonic's TaskStepSpec has no imagePullPolicy
// field to set, and pinning a digest would need a bump on every CLI change.
//
// Building the CLI here costs nothing: ocidex-cli stays in shippedBinaries as its own
// SBOM subject, so this task compiles it either way — which is why ocidex-2u7y saved no
// build time and left dogfooding as its only benefit. Running the workspace binary
// keeps the CLI and the args below on the same commit, so neither mutable-tag pull
// semantics nor flag skew can break this task again.
const ocidexSource = "ocidex/ci";

// The binaries OCIDex ships — one image each in docker/Dockerfile, so one uploaded
// SBOM each. ocidex-cli is also the tool doing the pushing, but since ocidex-5dw it
// ships an image of its own, so it is a subject here like the rest — which is why
// switching the push to the published image saved no build time: this list, not the
// pushing, is what compiles it.
const shippedBinaries = [
  "ocidex",
  "scanner-worker",
  "oci-metadata-worker",
  "git-worker",
  "user-enricher-worker",
  "provenance-worker",
  "vuln-worker",
  "k8s-agent",
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
// has already built and published its images. Every step carries `onError: continue`,
// and reportOnlyStatusReporter is failOnError: false.
//
// Report-only must not mean silent, though — that combination is what let nine broken
// uploads pass as green for a full day (ocidex-qzz2). Because failOnError is false, a
// raised error marks only the sbom-push check red and leaves the pipeline succeeding,
// so push-sboms.nu raises on a genuine upload failure rather than logging and exiting
// 0. An unset API key stays a clean skip: nothing to do is not a failure.
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
      // each of the other steps. On a cluster with one untainted worker the honest
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

# A tag build is the released version; a push to main is not, so it gets a version
# that sorts below every release and still names the commit it came from.
#
# Written to disk rather than derived at push time: only this step has the params
# in scope, and push-sboms.nu hands the file straight to --version-file, which
# errors on a missing or blank file instead of pushing a versionless SBOM
# (ocidex-2u7y). Folded into this step rather than given one of its own: see the
# step-count note above.
let ref = "$(params.source-branch)"
let rev = "$(params.revision)"
let version = if ($ref | str starts-with "refs/tags/") {
  $ref | str replace "refs/tags/" ""
} else {
  $"0.0.0-($rev | str substring 0..7)"
}
$version | save -f .sbom-bins/.version
log $"OK: binaries built for (open .sbom-bins/.goarch | str trim) as version ($version)"
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

    // One step looping over shippedBinaries, on goImage — already pulled by
    // build-binaries in this same pod, so it costs no extra pull, and its shell is
    // what makes the API-key skip and the aggregate summary possible at all.
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
          // skip path in the script, rather than a CreateContainerConfigError that
          // would fail the pod before any step runs.
          name: "OCIDEX_API_KEY",
          valueFrom: {
            secretKeyRef: { name: "ocidex-api-key", key: "key", optional: true },
          },
        },
        { name: "OCIDEX_SOURCE", value: ocidexSource },
        { name: "OCIDEX_BINARIES", value: shippedBinaries.join(" ") },
      ],
      script: scriptFromFile(path.join(__dirname, "push-sboms.nu")),
      onError: "continue",
    },
  ],
});
