// @vitest-environment happy-dom
import { describe, it, expect } from "vitest";
import { clusterNames, runningForVersion, type RunningWorkload } from "./RunningTab";

function row(o: Partial<RunningWorkload>): RunningWorkload {
    return {
        id: "w",
        clusterId: "c",
        clusterName: "prod",
        k8sNamespace: "apps",
        workloadKind: "Deployment",
        workloadName: "api",
        containerName: "api",
        imageRef: "ghcr.io/x/api:1",
        podCount: 1,
        matchState: "exact",
        firstSeenAt: "2026-01-01T00:00:00Z",
        lastSeenAt: "2026-01-01T00:00:00Z",
        ...o,
    };
}

describe("running helpers (ocidex-70eo.8)", () => {
    it("names each cluster once, sorted", () => {
        expect(clusterNames([row({ clusterName: "b" }), row({ clusterName: "a" }), row({ clusterName: "b" })])).toEqual(["a", "b"]);
    });

    // One version can have an SBOM per platform; a workload matched through
    // the other platform's SBOM still runs this version.
    it("matches a version by SBOM or by version key", () => {
        const rows = [
            row({ clusterName: "by-sbom", sbomId: "s1", subjectVersion: "v1" }),
            row({ clusterName: "by-key", sbomId: "s2", subjectVersion: "v1.4.0" }),
            row({ clusterName: "other", sbomId: "s3", subjectVersion: "v1.5.0" }),
        ];
        expect(clusterNames(runningForVersion(rows, "s1", "v1.4.0"))).toEqual(["by-key", "by-sbom"]);
    });
});
