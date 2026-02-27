#!/usr/bin/env nu

# Strip the registry hostname from a repo path.
# e.g. registry.access.redhat.com/ubi10/minimal -> ubi10/minimal
#      quay.io/lib/ubuntu -> lib/ubuntu
def local-repo [repo: string] {
    let parts = ($repo | split row "/")
    if ($parts | first | str contains ".") {
        $parts | skip 1 | str join "/"
    } else {
        $repo
    }
}

def main [
    base_url: string = "http://localhost:8080/api/v1"
    zot_addr: string = "localhost:5000"
] {
    # Docker credential workaround: bypass credential helpers for anonymous access.
    let docker_config_dir = (^mktemp -d | str trim)
    '{}' | save --force $"($docker_config_dir)/config.json"
    $env.DOCKER_CONFIG = $docker_config_dir

    let image_sets = [
        { repo: "registry.access.redhat.com/ubi10", pattern: '^10\.[0-9]',           count: 3, desc: "Red Hat UBI 10"      }
        { repo: "quay.io/lib/ubuntu",               pattern: '^22\.[0-9]+$',          count: 3, desc: "Ubuntu 22"           }
        { repo: "quay.io/lib/alpine",               pattern: '^3\.[0-9]+$',           count: 3, desc: "Alpine 3"            }
        { repo: "quay.io/lib/traefik",              pattern: '^v3\.5\.[0-9]+$',       count: 3, desc: "Traefik v3.5"        }
        { repo: "quay.io/keycloak/keycloak",        pattern: '^26\.[0-9]+\.[0-9]+$',  count: 3, desc: "Keycloak 26"         }
        { repo: "quay.io/ceph/ceph",                pattern: '^v19\.[0-9]+\.[0-9]+$', count: 3, desc: "Ceph v19"            }
        { repo: "quay.io/lib/amazonlinux",          pattern: '^2023\.7\.',            count: 3, desc: "Amazon Linux 2023.7" }
    ]

    # Discover tags for all repos in parallel.
    print "Discovering tags...\n"
    let all_images = ($image_sets | par-each { |entry|
        let result = (do { ^oras repo tags $entry.repo } | complete)
        if $result.exit_code != 0 {
            print $"  WARN [($entry.desc)]: could not list tags, skipping."
            []
        } else {
            let matched = (
                $result.stdout
                | lines
                | where { |t| $t != "" and ($t =~ $entry.pattern) }
                | last $entry.count
            )
            if ($matched | is-empty) {
                print $"  WARN [($entry.desc)]: no tags matched '($entry.pattern)', skipping."
                []
            } else {
                let n = ($matched | length)
                let tag_list = ($matched | str join ", ")
                print $"  [($entry.desc)]: ($n) tags — ($tag_list)"
                $matched | each { |tag| $"($entry.repo):($tag)" }
            }
        }
    } | flatten)

    if ($all_images | is-empty) {
        rm -rf $docker_config_dir
        error make { msg: "No images discovered. Check network connectivity and registry access." }
    }

    let total = ($all_images | length)
    print $"\n===========================================\nTotal images to process: ($total)\n===========================================\n"

    # Copy all images to Zot in parallel.
    let results = ($all_images | enumerate | par-each { |item|
        let image = $item.item
        let idx = ($item.index + 1)

        # Split off tag from the full image ref (split on last ':').
        let parts = ($image | split row ":")
        let tag = ($parts | last)
        let repo = ($parts | drop 1 | str join ":")
        let dest = $"($zot_addr)/(local-repo $repo):($tag)"

        # Skip Docker-format manifests; oras copy only handles OCI indexes cleanly.
        let manifest = (do { ^oras manifest fetch $image } | complete)
        let is_docker = (
            if $manifest.exit_code == 0 {
                let media_type = (try { $manifest.stdout | from json | get -o mediaType | default "" } catch { "" })
                $media_type | str contains "vnd.docker"
            } else {
                false
            }
        )

        if $is_docker {
            print $"  [($idx)/($total)] SKIP  ($image) — Docker manifest format"
            { status: skip, image: $image }
        } else {
            let copy = (do { ^oras copy --to-plain-http $image $dest } | complete)
            if $copy.exit_code != 0 {
                print $"  [($idx)/($total)] SKIP  ($image) — oras copy failed"
                { status: skip, image: $image }
            } else {
                print $"  [($idx)/($total)] OK    ($image)"
                { status: ok, image: $image }
            }
        }
    })

    rm -rf $docker_config_dir

    let succeeded = ($results | where status == ok | length)
    let skipped   = ($results | where status == skip | length)

    print $"
===========================================
Seed complete.
  Succeeded: ($succeeded)
  Skipped:   ($skipped)
===========================================

Verify:
  curl -s ($base_url)/artifacts | from json | get data | select name type
"
}
