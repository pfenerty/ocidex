// @vitest-environment happy-dom
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render } from "@solidjs/testing-library";
import type { JSX } from "solid-js";
import {
    useMyMoves,
    useDiff,
    useMyActivity,
    useMyDriftFeed,
    useMyClusters,
    useMySeenOnlyImages,
} from "~/api/queries";
import { useAuth } from "~/context/auth";
import type { components } from "~/types/openapi";
import Dashboard, { fixLabel, receiptRows, shortImage } from "./index";
import { countSince } from "./StatusFooter";

vi.mock("~/api/queries", () => ({
    useMyMoves: vi.fn(),
    useDiff: vi.fn(),
    useMyActivity: vi.fn(),
    useMyDriftFeed: vi.fn(),
    useMyClusters: vi.fn(),
    useMySeenOnlyImages: vi.fn(),
}));

vi.mock("~/context/auth", () => ({ useAuth: vi.fn() }));

vi.mock("@solidjs/router", () => ({
    A: (props: { href: string; class?: string; children?: JSX.Element }) => (
        <a href={props.href} class={props.class}>
            {props.children}
        </a>
    ),
}));

type Moves = NonNullable<ReturnType<typeof useMyMoves>["data"]>;
type ComponentDiff = components["schemas"]["ComponentDiff"];

const tag = (t: string, id: string, builtAt = "2026-10-07T00:00:00Z") => ({ tag: t, sbomId: id, builtAt });

const moves: Moves = {
    source: "cluster",
    upgrades: [
        {
            artifactId: "a-dex",
            image: "ghcr.io/dexidp/dex",
            namespaces: ["auth"],
            pods: 2,
            running: tag("v2.45.1", "s-run"),
            target: tag("v2.46.1", "s-target"),
            firstBetter: tag("v2.46.0", "s-first"),
            waitingDays: 47,
            before: { critical: 16, high: 89 },
            after: { critical: 2, high: 36 },
            alternative: { ...tag("v2.46.1-distroless", "s-alt"), after: { critical: 1, high: 21 } },
        },
        {
            artifactId: "a-pg",
            image: "ghcr.io/cloudnative-pg/postgresql",
            namespaces: ["databases"],
            pods: 1,
            running: tag("18.6", "p-run"),
            target: tag("18.7", "p-target"),
            firstBetter: tag("18.7", "p-target"),
            waitingDays: 11,
            before: { critical: 1, high: 47 },
            after: { critical: 1, high: 45 },
        },
    ],
    leftoverCriticals: [
        { id: "CVE-2026-6653", cvssScore: 9.8, package: "libxml2", packageVersion: "2.9.14", fixState: "wont-fix", images: ["ghcr.io/cloudnative-pg/postgresql"] },
        { id: "CVE-2026-4738", cvssScore: 9.4, package: "zlib", packageVersion: "1.3.2-r1", fixedVersion: "1.4-r0", fixState: "fixed", images: ["ghcr.io/dexidp/dex"] },
    ],
    namespaces: [
        { name: "auth", images: 1, pods: 2, before: { critical: 16, high: 89 }, after: { critical: 2, high: 36 } },
        { name: "databases", images: 1, pods: 1, before: { critical: 1, high: 47 }, after: { critical: 1, high: 45 } },
    ],
    totals: {
        images: 2,
        pods: 3,
        before: { critical: 17, high: 136 },
        after: { critical: 3, high: 81 },
        upgrades: 2,
        upgradesCutCritical: 1,
        longestWaitDays: 47,
        longestWaitImage: "ghcr.io/dexidp/dex",
        leftoverCriticals: 2,
    },
};

const change = (name: string, closes: string[], opens: string[] = []): ComponentDiff => ({
    name,
    type: "modified",
    direction: "upgraded",
    version: "2",
    previousVersion: "1",
    closes: closes.map((s, i) => ({ id: `CVE-${name}-${i}`, severity: s as "CRITICAL" })),
    opens: opens.map((s, i) => ({ id: `CVE-${name}-o${i}`, severity: s as "CRITICAL" })),
});

const loaded = <T,>(data: T) => ({ isLoading: false, isError: false, error: undefined, data });

beforeEach(() => {
    vi.mocked(useAuth).mockReturnValue({ user: () => ({ displayName: "Pat" }) } as never);
    vi.mocked(useMyMoves).mockReturnValue(loaded(moves) as never);
    vi.mocked(useDiff).mockReturnValue(
        loaded({ changes: [change("libssl3", ["CRITICAL", "HIGH"]), change("busybox", []), change("otel", [], ["MEDIUM"])] }) as never,
    );
    vi.mocked(useMyActivity).mockReturnValue(loaded({ data: [] }) as never);
    vi.mocked(useMyDriftFeed).mockReturnValue(loaded({ data: [] }) as never);
    vi.mocked(useMyClusters).mockReturnValue(
        loaded({ data: [{ id: "c1", name: "homelab", lastSeenAt: new Date().toISOString() }] }) as never,
    );
    vi.mocked(useMySeenOnlyImages).mockReturnValue(loaded([{ imageDigest: "d" }]) as never);
});

describe("Dashboard", () => {
    it("renders the KPI strip from the moves totals", () => {
        const { getByLabelText } = render(() => <Dashboard />);
        const kpi = getByLabelText("Fleet summary").textContent;
        expect(kpi).toContain("2 images · 3 pods");
        expect(kpi).toContain("17 3 after upgrades");
        expect(kpi).toContain("136 81 after");
        expect(kpi).toContain("2 1 cut criticals");
        expect(kpi).toContain("47 d dex");
    });

    it("lists upgrades in the order the API ranked them, with deltas and a diff link", () => {
        const { getByLabelText } = render(() => <Dashboard />);
        const table = getByLabelText("Upgrades");
        const rows = table.querySelectorAll(".ws-up-row");
        expect(rows).toHaveLength(2);
        expect(rows[0].textContent).toContain("dex");
        expect(rows[0].textContent).toContain("16 → 2−14");
        expect(rows[0].querySelector("a")?.getAttribute("href")).toBe("/diff?from=s-run&to=s-target");
        expect(rows[1].textContent).toContain("1 → 1±0");
        expect(table.querySelector(".ws-up-total")?.textContent).toContain("17 → 3−14");
    });

    it("expands a row into the running-to-target receipt", () => {
        const { getByLabelText, getAllByRole } = render(() => <Dashboard />);
        const table = getByLabelText("Upgrades");
        expect(table.querySelector(".ws-receipt")).toBeNull();
        fireEvent.click(getAllByRole("button")[0]);
        const receipt = table.querySelector(".ws-receipt")?.textContent ?? "";
        expect(vi.mocked(useDiff)).toHaveBeenCalled();
        expect(receipt).toContain("3 package changes");
        expect(receipt).toContain("1 close a CVE");
        expect(receipt).toContain("1 open one");
        expect(receipt).toContain("libssl3");
        expect(receipt).toContain("v2.46.1-distroless instead: criticals 1, highs 21");
    });

    it("renders leftover criticals and namespaces", () => {
        const { getByLabelText } = render(() => <Dashboard />);
        const left = getByLabelText("Criticals left after upgrades").textContent;
        expect(left).toContain("CVE-2026-6653");
        expect(left).toContain("won't fix");
        expect(left).toContain("1.4-r0 upstream, no tag ships it yet");
        const ns = getByLabelText("By namespace").querySelectorAll(".ws-ns");
        expect(ns).toHaveLength(3); // header + 2
        expect(ns[1].textContent).toContain("auth");
    });

    it("has no panel grid any more", () => {
        const { container } = render(() => <Dashboard />);
        expect(container.querySelector(".dash-grid")).toBeNull();
    });

    it("says so when nothing runs", () => {
        vi.mocked(useMyMoves).mockReturnValue(
            loaded({ ...moves, upgrades: [], totals: { ...moves.totals, images: 0 } }) as never,
        );
        const { getByText } = render(() => <Dashboard />);
        expect(getByText("Nothing running or owned yet.")).toBeTruthy();
    });

    it("shows the status footer", () => {
        const { container } = render(() => <Dashboard />);
        const footer = container.querySelector(".ws-footer")?.textContent ?? "";
        expect(footer).toContain("Running, no SBOM1 images");
        expect(footer).toContain("homelab");
    });
});

describe("helpers", () => {
    it("receiptRows keeps CVE-closing changes, most criticals first", () => {
        const rows = receiptRows([change("a", ["HIGH", "HIGH", "HIGH"]), change("b", []), change("c", ["CRITICAL"])]);
        expect(rows.map((r) => r.name)).toEqual(["c", "a"]);
    });

    it("fixLabel distinguishes an unshipped fix, won't fix and no fix", () => {
        expect(fixLabel({ id: "x", package: "p", images: [], fixedVersion: "1.4" })).toBe("upstream, no tag ships it yet");
        expect(fixLabel({ id: "x", package: "p", images: [], fixState: "wont-fix" })).toBe("won't fix");
        expect(fixLabel({ id: "x", package: "p", images: [], fixState: "not-fixed" })).toBe("no fix yet");
        expect(fixLabel({ id: "x", package: "p", images: [] })).toBe("no fix known");
    });

    it("shortImage keeps the last path segment", () => {
        expect(shortImage("ghcr.io/fluxcd/kustomize-controller")).toBe("kustomize-controller");
    });

    it("countSince counts rows inside the window", () => {
        const now = Date.parse("2026-11-23T12:00:00Z");
        const rows = ["2026-11-23T01:00:00Z", "2026-11-20T00:00:00Z", "2026-11-01T00:00:00Z"];
        expect(countSince(rows, (r) => r, 1, now)).toBe(1);
        expect(countSince(rows, (r) => r, 7, now)).toBe(2);
    });
});
