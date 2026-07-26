import { Task, nu } from "@pfenerty/tektonic";
import { govulncheckImage, goEnv, goCache, reportOnlyStatusReporter } from "../../shared";
import { goSetup } from "../../script-lib";

// Reachability-aware Go vuln scan. Unlike grype-on-SBOM (jobs/go-security), govulncheck
// resolves the MVS-selected module versions and walks the call graph to report only vulns
// actually reachable from ocidex's code — no phantom-version noise. Go-only + needs the
// toolchain, so it's its own task. Report-only: non-zero exit (reachable vulns) becomes this
// task's GitHub check while the PipelineRun stays green.
export const goVulncheck = new Task({
  name: "govulncheck-scan",
  statusReporter: reportOnlyStatusReporter,
  caches: [goCache],
  stepTemplate: {
    env: goEnv,
  },
  steps: [
    {
      name: "govulncheck-scan",
      image: govulncheckImage,
      // govulncheck builds a whole-program SSA call graph for reachability analysis, which is
      // very memory-hungry on ocidex's dep graph (grype/syft/AWS-SDK/k8s) — it OOMKilled at 2Gi,
      // then 4Gi, then 6Gi (ocidex-2w2). The 6Gi OOM was confirmed NOT a node-headroom problem —
      // the pod landed on the cluster's largest node with 11GB+ free and still hit its own 6Gi
      // cgroup ceiling in under 90s. A local run against the same ./cmd/... target measured
      // ~3.2GB peak RSS; the gap to 6Gi is plausibly cgroup page-cache accounting on the
      // restored GOMODCACHE/GOCACHE archive, which grows with the heavier dep tree the
      // ocidex-goh provenance epic added (cosign, sigstore-go, rekor, in-toto). Raise to 10Gi
      // with real margin over the observed baseline; the node has capacity for it.
      computeResources: {
        limits: { cpu: "2", memory: "10Gi", "ephemeral-storage": "4Gi" },
        requests: { cpu: "500m", memory: "2Gi", "ephemeral-storage": "2Gi" },
      },
      // Scan from the command entry points (./cmd/...) rather than ./... : it still follows every
      // import the binaries actually use (so no production vuln is missed), but drops test files
      // and unreachable internal packages — a smaller call graph, and a more accurate "reachable
      // in what we ship" than including _test.go entry points.
      script: nu`
${goSetup}
log "Running govulncheck ./cmd/..."
^govulncheck ./cmd/...
log "OK: no reachable vulnerabilities"
`,
    },
  ],
});
