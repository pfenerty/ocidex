#!/usr/bin/env nu

# Seeds an OCIDex instance with real SBOMs by registering well-annotated public
# OCI repositories and triggering a scan on each. The scanner-worker walks the
# catalog, runs syft per image, and ingests the resulting SBOMs — so seeding is
# asynchronous and continues in the background after this script exits.
#
# Requires an API key with write scope: log in via GitHub OAuth, then create one
# in the UI under Settings -> API Keys.
#
# Usage:
#   export OCIDEX_API_KEY=ocidex_...
#   nu scripts/seed.nu
#   nu scripts/seed.nu --api-key ocidex_... --base-url http://myhost:8080/api/v1
#   nu scripts/seed.nu --all-tags          # every semver tag, not just the pinned minors
#   nu scripts/seed.nu --no-scan           # register only, let the poll interval pick it up
#
# All repos are verified to carry org.opencontainers.image.version in manifest
# annotations or config labels. quay.io/lib/ is excluded — that namespace was
# shut down by Quay in May 2025.

# Tag globs are deliberately narrow: they yield a handful of versions per
# artifact, which is enough to exercise diff, changelog, and version history
# without queueing every release ever published. As configured below this is 45
# images across 11 repos. `--all-tags` swaps them all for "semver".
#
# Patterns run through Go's path.Match server-side (internal/service/registry.go
# matchGlob), so `*` and `?` work but regular expressions do not. Two rules follow
# from that, both learned by measuring these globs against live tag lists:
#
#   1. Use `?` for the patch digit, not `*`. `v3.7.*` matches 78 traefik tags —
#      every -nanoserver/-windowsservercore/-ea/-rc variant — because path.Match's
#      `*` runs to end of string and there is no negation. `v3.7.?` matches only
#      single-digit patches, which is exactly the clean Linux release set. The
#      cost is that patch 10 and up are skipped; for seed data that is fine.
#   2. tag_patterns apply to every repo in the entry, and matching is OR across
#      the list. So only group repos that share a version line — mixing lines
#      cross-matches (adding skopeo's "v1.9.?" to this first entry also drags in
#      podman's 2020-era v1.9.x). Repos on their own line get their own entry.
def registry-table [] {
    [
        # quay.io repos — no catalog API, repos listed explicitly.
        # containers/* has OCI manifest annotations (version+created).
        # keycloak and metallb carry version in config labels.
        #
        # Enrichment notes (git-commit + provenance enrichers, checked against live images):
        # - buildah/podman/skopeo source.image annotation points at a blob/<sha>/subdir URL
        #   into the containers/image_build monorepo — git enrichment resolves this correctly.
        # - No cosign signatures/attestations found on these images — provenance stays absent.
        #
        # skopeo is deliberately omitted: it is on v1.9.x, which collides with podman's
        # 2020-era v1.9.x under rule 2 above. buildah and podman cover the same
        # enrichment behaviour between them.
        {
            name: "Quay.io — Container Tools (Red Hat)"
            type: "generic"
            url: "quay.io"
            repositories: [
                "containers/buildah"
                "containers/podman"
            ]
            tag_patterns: ["v5.8.?" "v1.43.?"]   # podman, buildah
        }
        # Enrichment notes: source annotation points at keycloak-rel/keycloak-rel, a
        # release-packaging mirror, not the keycloak/keycloak upstream repo — git
        # enrichment "succeeds" but resolves commits against the mirror, not upstream.
        # No provenance attestations found.
        {
            name: "Quay.io — Keycloak"
            type: "generic"
            url: "quay.io"
            repositories: ["keycloak/keycloak"]
            tag_patterns: ["26.4.?"]
        }
        # Enrichment notes: clean source+revision annotations, git enrichment resolves
        # correctly against metallb/metallb. No provenance attestations found.
        {
            name: "Quay.io — MetalLB"
            type: "generic"
            url: "quay.io"
            repositories: ["metallb/controller" "metallb/speaker"]
            tag_patterns: ["v0.15.?"]
        }
        # ghcr.io repos — type "ghcr" enables untagged manifest discovery.
        # traefik has OCI manifest annotations (version+created).
        # fluxcd controllers and dex carry version in config labels.
        #
        # Enrichment notes: traefik's *manifest-annotation* source/revision (from
        # Docker-Official-Images tooling) point at traefik/traefik-library-image, not
        # the actual traefik/traefik repo carried in the config-label source — oci.go's
        # extractField prefers manifest annotations, so git enrichment resolves commits
        # against the wrong repo here. No provenance attestations found.
        #
        # traefik publishes both "3.7.x" and "v3.7.x" for the same digest; the glob
        # only matches the v-prefixed form, and the scanner digest-dedups regardless.
        {
            name: "GHCR — Traefik"
            type: "ghcr"
            url: "ghcr.io"
            repositories: ["traefik/traefik"]
            tag_patterns: ["v3.7.?"]
        }
        # Enrichment notes: clean source+revision annotations, git enrichment resolves
        # correctly. These share a large Go dependency set, which is what makes
        # component search across artifacts interesting on a seeded instance.
        #
        # Only the three controllers that share the v1.9 line are listed. flux-cli
        # (v2.9), helm-controller (v1.6), and image-reflector-controller (v1.2) are
        # each on their own line and would need their own entry — see rule 2 above.
        {
            name: "GHCR — Flux Controllers"
            type: "ghcr"
            url: "ghcr.io"
            repositories: [
                "fluxcd/source-controller"
                "fluxcd/kustomize-controller"
                "fluxcd/notification-controller"
            ]
            tag_patterns: ["v1.9.?"]
        }
        # Enrichment notes: clean source+revision annotations, git enrichment resolves
        # correctly. Publishes a real SLSA provenance attestation as a Sigstore Bundle
        # referrer (application/vnd.dev.sigstore.bundle.v0.3+json) — recognized by the
        # provenance enricher.
        {
            name: "GHCR — Dex OIDC"
            type: "ghcr"
            url: "ghcr.io"
            repositories: ["dexidp/dex"]
            tag_patterns: ["v2.45.?"]
        }
    ]
}

# Fail fast, and readably, when nothing is listening. Without this every POST
# below returns a bare connection error and the real cause — "the stack isn't
# running" — is buried under six of them.
def check-api [base_url: string] {
    let health = ($base_url | str replace --regex '/api/v1/?$' '') + "/health"
    # try/catch, not `do {} | complete`: `complete` only captures exit codes from
    # external commands, so a connection refused from the internal `http get`
    # propagates straight out and buries the actionable message.
    #
    # The catch returns a sentinel rather than raising: `error make` *inside* a
    # catch block re-surfaces the original error (nu 0.113 renders the caught
    # I/O error, not the new message), so the raise has to happen outside.
    let status = (try {
        (http get --full --allow-errors --max-time 5sec $health).status
    } catch {
        0
    })
    if $status == 0 {
        error make { msg: $"OCIDex is not reachable at ($health).\nStart the stack first: 'docker compose up -d' or 'make dev-up'." }
    }
    if $status != 200 {
        error make { msg: $"OCIDex health check at ($health) returned ($status), expected 200." }
    }
}

# registry.name is globally UNIQUE, so a second run gets 409 on every entry.
# Resolve the existing ID instead of skipping, so re-seeding is a no-op plus a
# fresh scan rather than a failure.
# limit=200 is the endpoint maximum; the default of 20 would miss the match on an
# instance that already has more registries than one page.
def resolve-existing [base_url: string, headers: record, name: string] {
    let resp = (http get --full --allow-errors --headers $headers $"($base_url)/registries?limit=200")
    if $resp.status != 200 {
        return null
    }
    $resp.body.data | where name == $name | get -o 0.id
}

def main [
    --base-url: string = "http://localhost:8080/api/v1"
    --api-key: string = ""      # Bearer API key; falls back to $env.OCIDEX_API_KEY
    --poll-interval: int = 360  # Poll interval in minutes (default: 6 hours)
    --all-tags                  # Ingest every semver tag instead of the pinned minor per repo
    --no-scan                   # Register only; do not trigger an immediate scan
    --timeout: int = 600        # Seconds to wait for the first artifacts to appear
] {
    let key = if ($api_key | is-empty) { $env.OCIDEX_API_KEY? | default "" } else { $api_key }
    if ($key | is-empty) {
        error make { msg: "API key required. Pass --api-key <key> or set OCIDEX_API_KEY.\nCreate one in the UI under Settings -> API Keys after logging in with GitHub." }
    }

    check-api $base_url

    let headers = { "Authorization": $"Bearer ($key)" }
    let registries = (registry-table)

    print $"Creating ($registries | length) registries against ($base_url)\n"

    let created = ($registries | each { |reg|
        let patterns = if $all_tags { ["semver"] } else { $reg.tag_patterns }
        let body = {
            name: $reg.name
            type: $reg.type
            url: $reg.url
            insecure: false
            repositories: $reg.repositories
            repository_patterns: []
            tag_patterns: $patterns
            scan_mode: "poll"
            poll_interval_minutes: $poll_interval
            visibility: "public"
        }

        let resp = (http post --full --allow-errors --content-type application/json --headers $headers $"($base_url)/registries" $body)

        if $resp.status == 201 {
            print $"  OK      ($reg.name) → ($resp.body.id)"
            { name: $reg.name, id: $resp.body.id }
        } else if $resp.status == 409 {
            let existing = (resolve-existing $base_url $headers $reg.name)
            if ($existing | is-empty) {
                print $"  FAIL    ($reg.name): 409 but could not resolve the existing registry"
                null
            } else {
                print $"  EXISTS  ($reg.name) → ($existing)"
                { name: $reg.name, id: $existing }
            }
        } else {
            print $"  FAIL    ($reg.name): ($resp.status) ($resp.body)"
            null
        }
    } | compact)

    if ($created | is-empty) {
        error make { msg: $"No registries were created or resolved. Check that the API key has write scope and that ($base_url) is the right instance." }
    }

    print $"\n($created | length) of ($registries | length) registries ready."

    if $no_scan {
        print $"Skipping scans \(--no-scan\). Images will be picked up within ($poll_interval) minutes."
        return
    }

    print "\nTriggering scans..."
    for entry in $created {
        # --content-type is required even though the endpoint takes no body: nu
        # rejects a record payload without it ("Accepted types: [binary, string]").
        let resp = (http post --full --allow-errors --content-type application/json --headers $headers $"($base_url)/registries/($entry.id)/scan" {})
        if $resp.status == 202 {
            print $"  SCAN    ($entry.name)"
        } else {
            print $"  FAIL    scan ($entry.name): ($resp.status)"
        }
    }

    # Scanning is asynchronous: the 202 above only queues the catalog walk, and
    # each matched image then needs a syft run in scanner-worker. Wait for the
    # *first* artifacts so the script can distinguish "seeding started" from the
    # silent no-op this replaced — not for the full set, which takes far longer.
    print $"\nWaiting up to ($timeout)s for the first artifacts to land..."
    mut waited = 0
    mut artifacts = []
    mut total = 0
    while $waited < $timeout {
        sleep 10sec
        $waited = $waited + 10
        # /artifacts is cursor-paginated — the response carries hasMore, not a
        # total — so the count below is "artifacts on this page", not a grand total.
        let resp = (http get --full --allow-errors --headers $headers $"($base_url)/artifacts?limit=100")
        if $resp.status == 200 {
            $artifacts = ($resp.body.data | default [])
            $total = ($artifacts | length)
            if not ($artifacts | is-empty) { break }
        }
        print $"  ... ($waited)s"
    }

    if ($artifacts | is-empty) {
        # Parens are escaped: in an interpolated string nu evaluates `(...)` as a
        # subexpression, so an unescaped "(docker compose logs ...)" runs as a command.
        error make { msg: $"No artifacts appeared within ($timeout)s.\nRegistries were created, but nothing was ingested — check the scanner-worker logs\n\('docker compose logs scanner-worker', or the ocidex-scanner-worker resource in Tilt\)." }
    }

    let names = ($artifacts | get name | first 5 | str join ", ")
    print $"
===========================================
Seeding underway.
  Registries: ($created | length)
  Artifacts so far: ($total) — ($names)
===========================================

Scanning continues in the background. Watch progress with:
  curl -s -H 'Authorization: Bearer <key>' '($base_url)/artifacts?limit=100' | from json | get data | length
"
}
