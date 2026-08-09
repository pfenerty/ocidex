import { Task, nu } from "@pfenerty/tektonic";
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

// The published CLI does the pushing (ocidex-2u7y). `:main`, not the current
// commit's `sha-` tag, and deliberately: this task runs before the image-build
// chain, so the only ocidex-cli image that exists when it starts is the previous
// commit's. Gating on image-build-cli instead would fix the staleness but delay
// the upload by the ~60m image chain and skip the dogfooding entirely whenever an
// image build fails — which is when it is most worth having run.
//
// The consequence to keep in mind when changing the args below: they are consumed
// by a CLI built one commit ago, so a newly added flag does not exist there until
// the following run. That is not hypothetical — it happened on the commit that
// introduced this arrangement. --version-file and --arch-file landed together with
// these steps, so the first push pipeline after the merge ran ten push steps
// against a CLI that had never heard of either flag: cobra printed usage, every
// step exited 2, and the task still reported green (onError: continue). The run
// after that, which pulled a :main built from this commit, worked.
//
// So: a change that adds a flag here costs one degraded, self-healing run. If that
// is ever not acceptable, land the CLI change on its own first and flip the args in
// a follow-up commit.
const cliImage = "ghcr.io/pfenerty/ocidex-cli:main";
const ocidexSource = "ocidex/ci";

// The binaries OCIDex ships — one image each in docker/Dockerfile, so one uploaded
// SBOM each. ocidex-cli is also the tool doing the pushing, but since ocidex-5dw it
// ships an image of its own, so it is a subject here like the rest — which is why
// switching the push to the published image saved no build time: this list, not the
// pushing, is what compiles it.
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
// has already built and published ten images. Every step therefore carries
// `onError: continue`, which is what keeps the task green regardless.
//
// Two things that the single nushell push step used to do are gone with it, both
// worth knowing before reading a confusing TaskRun (ocidex-2u7y):
//
//   - No clean skip when OCIDEX_API_KEY is unset. The old script logged one line and
//     exited 0. Tekton has no step-level `when`, so a cluster without the
//     ocidex-api-key secret now gets ten failed-but-continued push steps instead of
//     one skip. Noisy, not harmful.
//   - No aggregate summary. There is no "3 of 10 uploads failed" line any more;
//     failures show per-step in the TaskRun status, which is finer-grained but needs
//     the step list read rather than one log tail.
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

# A tag build is the released version; a push to main is not, so it gets a version
# that sorts below every release and still names the commit it came from.
#
# Computed here, in the last step of this task that has a shell, because the steps
# that consume it run the distroless ocidex-cli image and cannot derive it. They
# read it back via --version-file (ocidex-2u7y). Folded into this step rather than
# given one of its own: see the step-count note above.
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

    // One step per binary. The image is distroless, so there is no shell to loop
    // in — but shippedBinaries is already an array, and generating N steps from an
    // array is how the image-build chain is built too.
    //
    // The subject is declared rather than inferred: a syft scan of a binary names
    // the file it read, and the purl it derives is the Go *module*, which all ten
    // binaries share. Group + name are what keep them distinct artifacts.
    //
    // The purl carries no @version. artifact.purl is an attribute, not part of the
    // artifact's identity — UpsertArtifact conflicts on (type, name, group) — so a
    // versioned purl only churned the stored value on every push while the version
    // that matters lives on sbom.subject_version. It also keys the same way ADR-019
    // Rule 1 and ADR-041 do, on the purl base.
    ...shippedBinaries.map((b) => ({
      name: `push-${b}`,
      image: cliImage,
      command: ["/ocidex-cli"],
      args: [
        "sbom", "push", `.sbom-out/${b}.cdx.json`,
        "--source", ocidexSource,
        "--artifact-file", `.sbom-bins/${b}`,
        "--subject-type", "application",
        "--subject-name", b,
        "--subject-group", "github.com/pfenerty/ocidex",
        "--subject-purl", `pkg:golang/github.com/pfenerty/ocidex/cmd/${b}`,
        "--version-file", ".sbom-bins/.version",
        "--arch-file", ".sbom-bins/.goarch",
      ],
      // Ten steps' requests are held for the whole task (see the note on
      // build-binaries), so these are as small as a one-shot HTTP POST can ask for.
      computeResources: {
        limits: { cpu: "250m", memory: "128Mi" },
        requests: { cpu: "25m", memory: "64Mi" },
      },
      env: [
        {
          name: "OCIDEX_URL",
          value: "http://ocidex-dev-api.ocidex-dev.svc.cluster.local",
        },
        {
          // optional so a cluster without the secret gets an empty key and a clean
          // "no API key" error, rather than a CreateContainerConfigError that would
          // fail the pod before any step runs.
          name: "OCIDEX_API_KEY",
          valueFrom: {
            secretKeyRef: { name: "ocidex-api-key", key: "key", optional: true },
          },
        },
      ],
      onError: "continue" as const,
    })),
  ],
});
