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
 * The sweep is complete — .24 took pages/admin/** (Dashboard and ClusterDetail
 * were already clean), .25 the rest — so the scope below is the whole of src
 * and ALLOWED is exhaustive. MIGRATED is kept as a named list so the second
 * test can assert each of those files actually reaches for the primitive,
 * rather than merely not naming the class.
 */
const MIGRATED = [
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

/** index.css with its comments stripped, for the same reason `code()` exists. */
function css(): string {
    return readFileSync(join(SRC, "index.css"), "utf-8").replace(/\/\*[\s\S]*?\*\//g, "");
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

    it("reaches for a primitive that emits one", () => {
        // `DataTable` counts: it renders its own `<Card>`, so a page that moved
        // its table onto the table primitive (ocidex-ag4q.26) has stopped
        // naming `Card` directly and is more migrated, not less.
        const missing = MIGRATED.filter((f) => !/\b(Card|DataTable)\b/.test(code(join(SRC, f))));
        expect(missing).toEqual([]);
    });
});

describe("card markup is emitted from nowhere else", () => {
    it("is confined to the primitives", () => {
        const offenders = sources(SRC)
            .filter((f) => RAW_CARD.test(code(f)))
            .map((f) => relative(SRC, f))
            .filter((f) => !ALLOWED.includes(f));
        expect(offenders).toEqual([]);
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
        const src = css();
        for (const tone of ["success", "warning"]) {
            const rule = new RegExp(`\\.card-${tone}\\s*\\{([^}]*)\\}`).exec(src);
            if (rule === null) throw new Error(`no .card-${tone} rule in index.css`);
            expect(rule[1]).toContain(`var(--color-${tone})`);
            expect(src).toMatch(new RegExp(`--color-${tone}:\\s*#[0-9A-Fa-f]{6}`));
        }
    });
});

describe(".title-inline", () => {
    // Five headings set `display: flex` as an inline style on their own h2/h3.
    // An inline style is the one thing a stylesheet cannot restyle and a
    // contract test cannot see, so the rule has to exist for real.
    it("is a real rule, and the last inline flex heading is gone", () => {
        const rule = /\.title-inline\s*\{([^}]*)\}/.exec(css());
        if (rule === null) throw new Error("no .title-inline rule in index.css");
        expect(rule[1]).toContain("display: flex");

        const offenders = sources(SRC)
            .filter((f) => /<h[23]\b[\s\S]{0,120}?display: "flex"/.test(code(f)))
            .map((f) => relative(SRC, f));
        expect(offenders).toEqual([]);
    });

    it("is what makes the icon shrink guard on card headings mean anything", () => {
        // `.card-header h3` is not a flex container, so shrink on its svg child
        // is inert unless something inside the h3 establishes the flex context.
        // If that declaration is ever deleted as dead, the icon headers start
        // squashing their icons instead.
        //
        // Read through `css()`, not raw: the prose above `.title-inline`
        // quotes this exact selector, and a test that its own documentation
        // satisfies is a test that asserts nothing.
        expect(css()).toMatch(/\.card-header h3 svg\s*\{[^}]*flex-shrink:\s*0/);
        const users = sources(SRC).filter((f) => code(f).includes('class="title-inline"'));
        expect(users.length).toBeGreaterThan(0);
    });
});
