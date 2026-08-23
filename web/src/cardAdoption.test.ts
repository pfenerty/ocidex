import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * `<Card>` / `<CardHeader>` are the one writer of the `card > card-header > h3`
 * shape (ocidex-ag4q.24, .25).
 *
 * Card.tsx's own doc comment says why: the nesting is what the CSS targets, and
 * `.card-header` is `justify-content: space-between` — so a hand-rolled header
 * that emits title, count and actions as three bare children strands the count
 * in the middle of the row, reading as a stray number rather than as this
 * heading's count. That is a layout bug with no failing assertion anywhere.
 *
 * MIGRATED grows as the sweep lands: .24 covers pages/admin/** (Dashboard and
 * ClusterDetail were already clean), .25 the rest.
 */
const MIGRATED = [
    "pages/admin/APIKeysTab.tsx",
    "pages/admin/StatusTab.tsx",
    "pages/admin/sources/NamespaceGroups.tsx",
    "pages/admin/sources/RegistryFormDialog.tsx",
    "pages/admin/sources/WebhookSecretBanner.tsx",
];

/**
 * `Modal` renders a dialog whose chrome *is* a card header, and `Skeleton`
 * stands in for a card that has not loaded — both must emit the markup rather
 * than import the thing they replace.
 */
const ALLOWED = ["components/ui/Card.tsx", "components/ui/Modal.tsx", "components/Skeleton.tsx"];

const SRC = __dirname;

/** Source with comments stripped, so prose naming a class stops matching it. */
function code(file: string): string {
    return readFileSync(file, "utf-8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/\/\/[^\n]*/g, "");
}

function sources(dir: string, acc: string[] = []): string[] {
    for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) sources(full, acc);
        else if (full.endsWith(".tsx") && !full.endsWith(".test.tsx")) acc.push(full);
    }
    return acc;
}

/**
 * A bare `card` or `card-header` class. `details.card` is a separate documented
 * variant with its own `summary.card-summary` contract, and `stat-card` is an
 * unrelated rule in admin/Admin.css, so the lookbehind keeps both out — a plain
 * word boundary matches after a hyphen, because a hyphen is not a word
 * character.
 */
const RAW_CARD = /class="[^"]*(?<![-\w])card(-header)?(?![-\w])[^"]*"/;

describe("migrated pages use the Card primitive", () => {
    it("hand-writes no card markup", () => {
        const offenders = MIGRATED.filter((f) => RAW_CARD.test(code(join(SRC, f))));
        expect(offenders).toEqual([]);
    });

    it("imports it from the barrel", () => {
        const missing = MIGRATED.filter((f) => !/\bCard\b/.test(code(join(SRC, f))));
        expect(missing).toEqual([]);
    });
});

describe("card markup is emitted from nowhere else", () => {
    it("is confined to the primitives and the not-yet-migrated list", () => {
        const offenders = sources(SRC)
            .filter((f) => RAW_CARD.test(code(f)))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        // Part 2 (.25) empties this. Until then it is the exact remaining list,
        // so a *new* hand-written card still fails.
        expect(offenders).toEqual([
            "components/ComponentMetadata.tsx",
            "components/DataTable.tsx",
            "components/DiffEntryCard.tsx",
            "components/GitCommitCard.tsx",
            "components/ImageMetadataCard.tsx",
            "components/ProvenanceCard.tsx",
            "pages/ArtifactDetail/RelationshipsTab.tsx",
            "pages/Artifacts.tsx",
            "pages/Diff.tsx",
            "pages/HomeDiscovery.tsx",
            "pages/Lookup.tsx",
            "pages/SBOMDetail/PackagesTab.tsx",
            "pages/SBOMDetail/index.tsx",
            "pages/VulnerabilityDetail.tsx",
        ]);
    });
});

describe("the card-header title wrapper", () => {
    it("keeps the count beside the title, not marooned mid-row", () => {
        // Anchored at the header's opening tag: what matters is that the first
        // child is the title wrapper, and a regex hunting for the matching
        // `</div>` by counting tags would be guessing.
        const src = code(join(SRC, "components/ui/Card.tsx"));
        expect(src).toMatch(/<div class="card-header">\s*<div class="card-header-title">\s*<h3>/);
    });
});

describe("the announcing tones", () => {
    it("are real rules, not class names the stylesheet never heard of", () => {
        // The exact failure this sweep replaced: `page-header-badges` and
        // `tab-btn` were both spelled correctly and styled by nothing. A tone
        // prop that emits a dead class is the same bug with a nicer API.
        const css = readFileSync(join(SRC, "index.css"), "utf-8");
        for (const tone of ["success", "warning"]) {
            const rule = new RegExp(`\\.card-${tone}\\s*\\{([^}]*)\\}`).exec(css);
            if (rule === null) throw new Error(`no .card-${tone} rule in index.css`);
            expect(rule[1]).toContain(`var(--color-${tone})`);
            expect(css).toMatch(new RegExp(`--color-${tone}:\\s*#[0-9A-Fa-f]{6}`));
        }
    });
});
