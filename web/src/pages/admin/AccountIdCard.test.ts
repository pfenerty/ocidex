import { describe, it, expect } from "vitest";
import { accountBadges } from "./AccountIdCard";

const earned = (state: Parameters<typeof accountBadges>[0]) =>
    accountBadges(state).filter((b) => b.earned).map((b) => b.id);

describe("accountBadges", () => {
    const none = { namespaceIds: ["ns1"], sources: [], clusters: [], apiKeyCount: 0 };

    it("earns nothing on a new account, and shows every badge as an outline", () => {
        expect(earned(none)).toEqual([]);
        expect(accountBadges(none).map((b) => b.id)).toEqual(["registry", "cluster", "api-key"]);
    });

    it("earns each badge from the state behind it", () => {
        expect(
            earned({
                namespaceIds: ["ns1"],
                sources: [{ kind: "oci_registry", namespaceId: "ns1" }],
                clusters: [{ lastSeenAt: "2026-11-01T00:00:00Z" }],
                apiKeyCount: 1,
            }),
        ).toEqual(["registry", "cluster", "api-key"]);
    });

    // A registry in someone else's (public) namespace is not this account's.
    it("counts only registries in the account's own namespaces", () => {
        expect(earned({ ...none, sources: [{ kind: "oci_registry", namespaceId: "other" }] })).toEqual([]);
        expect(earned({ ...none, sources: [{ kind: "upload", namespaceId: "ns1" }] })).toEqual([]);
    });

    it("does not count a cluster that never reported", () => {
        expect(earned({ ...none, clusters: [{}] })).toEqual([]);
    });
});
