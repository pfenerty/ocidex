#!/usr/bin/env nu

# Creates registry entries in OCIDex for well-annotated public OCI repositories.
# All registries use poll mode. Run `make run` before executing this script.
#
# Usage:
#   nu scripts/add-public-registries.nu --api-key ocidex_...
#   nu scripts/add-public-registries.nu --api-key ocidex_... --scan
#   nu scripts/add-public-registries.nu --api-key ocidex_... --base-url http://myhost:8080/api/v1
#
# All repos verified to carry org.opencontainers.image.version in manifest
# annotations or config labels. quay.io/lib/ is excluded — that namespace
# was shut down by Quay in May 2025.

def main [
    --base-url: string = "http://localhost:8080/api/v1"
    --api-key: string = ""     # Bearer API key (create one in the UI under Settings → API Keys)
    --scan                     # Trigger an ad-hoc scan on each registry after creation
    --poll-interval: int = 360 # Poll interval in minutes (default: 6 hours)
] {
    let key = if ($api_key | is-empty) { $env.OCIDEX_API_KEY? | default "" } else { $api_key }
    if ($key | is-empty) {
        error make { msg: "API key required. Pass --api-key <key> or set OCIDEX_API_KEY." }
    }

    let registries = [
        # quay.io repos — no catalog API, repos listed explicitly.
        # containers/* has OCI manifest annotations (version+created).
        # keycloak and metallb carry version in config labels.
        {
            name: "Quay.io — Container Tools (Red Hat)"
            type: "generic"
            url: "quay.io"
            repositories: [
                "containers/buildah"
                "containers/podman"
                "containers/skopeo"
            ]
        }
        {
            name: "Quay.io — Keycloak"
            type: "generic"
            url: "quay.io"
            repositories: ["keycloak/keycloak"]
        }
        {
            name: "Quay.io — MetalLB"
            type: "generic"
            url: "quay.io"
            repositories: ["metallb/controller" "metallb/speaker"]
        }
        # ghcr.io repos — type "ghcr" enables untagged manifest discovery.
        # traefik has OCI manifest annotations (version+created).
        # fluxcd controllers and dex carry version in config labels.
        {
            name: "GHCR — Traefik"
            type: "ghcr"
            url: "ghcr.io"
            repositories: ["traefik/traefik"]
        }
        {
            name: "GHCR — Flux Controllers"
            type: "ghcr"
            url: "ghcr.io"
            repositories: [
                "fluxcd/flux-cli"
                "fluxcd/source-controller"
                "fluxcd/kustomize-controller"
                "fluxcd/helm-controller"
                "fluxcd/notification-controller"
                "fluxcd/image-reflector-controller"
            ]
        }
        {
            name: "GHCR — Dex OIDC"
            type: "ghcr"
            url: "ghcr.io"
            repositories: ["dexidp/dex"]
        }
    ]

    print $"Creating ($registries | length) registries against ($base_url)\n"

    let headers = { "Authorization": $"Bearer ($key)" }

    let created = ($registries | each { |reg|
        let body = {
            name: $reg.name
            type: $reg.type
            url: $reg.url
            insecure: false
            repositories: $reg.repositories
            repository_patterns: []
            tag_patterns: ["semver"]
            scan_mode: "poll"
            poll_interval_minutes: $poll_interval
            visibility: "public"
        }

        let resp = (http post --full --allow-errors --content-type application/json --headers $headers $"($base_url)/registries" $body)

        if $resp.status == 201 {
            print $"  OK    ($reg.name) → ($resp.body.id)"
            { name: $reg.name, id: $resp.body.id }
        } else {
            print $"  FAIL  ($reg.name): ($resp.status) ($resp.body)"
            null
        }
    } | compact)

    if $scan and (not ($created | is-empty)) {
        print $"\nTriggering ad-hoc scans..."
        for entry in $created {
            let resp = (http post --full --allow-errors --headers $headers $"($base_url)/registries/($entry.id)/scan" {})
            if $resp.status == 202 {
                print $"  SCAN  ($entry.name)"
            } else {
                print $"  FAIL  scan ($entry.name): ($resp.status)"
            }
        }
    }

    print $"\nDone. ($created | length) of ($registries | length) registries created."
    if not $scan {
        print "Run with --scan to trigger an immediate scan, or wait for the poll interval."
    }
}
