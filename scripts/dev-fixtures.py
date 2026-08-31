#!/usr/bin/env python3
"""Seeds the local dev-auth rig (scripts/dev-auth.sh) with a corpus.

Why this exists: the rig used to mint a user, an API key and one empty
namespace, which is enough to *reach* /clusters and /dashboard and not enough
to see anything on them. Every page it was built to unblock rendered its empty
state, so the two surfaces most in need of a browser -- ClusterDetail's
coverage band and its Workloads table -- stayed unverifiable.

Everything below goes in through the ordinary API, with the rig's own API key,
against this branch's server. There is no bypass and no fixture-only code
path; the one exception is the vulnerability store, which has no ingest
endpoint at all (cmd/vuln-worker pulls OSV over the network, and a local rig
must not depend on that), so those rows are written with psql.

Idempotent: every digest is derived from the artifact's own identity, so a
second run re-uploads the same SBOMs and the `sbom.digest` UNIQUE constraint
(ADR-040) turns them into no-ops rather than duplicates.

The corpus spans both tenants: devowner's `local` and `private-lab`, and
devoutsider's `outsider-lab`. Both sides must hold rows, because against an
empty namespace a cross-tenant 404 proves nothing.

Usage:
    python3 scripts/dev-fixtures.py           # reads .dev/dev-auth.env
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENVFILE = ROOT / ".dev" / "dev-auth.env"

# The two tenants the rig draws its authorization boundary between. `local` and
# `private-lab` belong to devowner; OUTSIDER_NS belongs to devoutsider, who is a
# member of nothing else.
OUTSIDER_NS = "outsider-lab"


# --------------------------------------------------------------------------
# Plumbing
# --------------------------------------------------------------------------

def load_env() -> dict:
    """Reads the key=value file dev-auth.sh writes. Not a dotenv parser."""
    if not ENVFILE.exists():
        die(f"{ENVFILE} not found -- run `make dev-auth-up` first")
    out = {}
    for line in ENVFILE.read_text().splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


def log(msg: str) -> None:
    print(f"\033[36m>\033[0m {msg}")


def die(msg: str):
    print(f"\033[31mx\033[0m {msg}", file=sys.stderr)
    raise SystemExit(1)


class API:
    def __init__(self, base: str, key: str):
        self.base = base.rstrip("/")
        self.key = key

    def _req(self, method: str, path: str, body=None, ctype="application/json"):
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.key}")
        if data is not None:
            req.add_header("Content-Type", ctype)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")
        except urllib.error.URLError as e:
            die(f"{method} {path}: {e.reason} -- is the rig up? (`make dev-auth-up`)")

    def get(self, path):
        return self._req("GET", path)

    def post(self, path, body=None, ctype="application/json"):
        return self._req("POST", path, body, ctype)

    def patch(self, path, body):
        return self._req("PATCH", path, body)


def psql(db_url: str, sql: str) -> None:
    r = subprocess.run(["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q"],
                       input=sql, text=True, capture_output=True)
    if r.returncode != 0:
        die(f"psql failed:\n{r.stderr.strip()}")


def digest_for(*parts) -> str:
    """A stable fake image digest. Deterministic so re-runs are idempotent."""
    return "sha256:" + hashlib.sha256("|".join(parts).encode()).hexdigest()


# --------------------------------------------------------------------------
# Corpus
# --------------------------------------------------------------------------

# Real package names, versions and SPDX ids. The point is not accuracy against
# any actual image -- it is that /components, /licenses and the diff views get
# purls with the shape they have in production (distro qualifiers, golang
# module paths, scoped npm names) rather than "pkg:generic/foo@1".
APK_ALPINE = [
    ("musl", "1.2.5-r0", "MIT"), ("busybox", "1.36.1-r29", "GPL-2.0-only"),
    ("ca-certificates-bundle", "20240705-r0", "MPL-2.0 AND MIT"),
    ("zlib", "1.3.1-r1", "Zlib"), ("openssl", "3.3.2-r0", "Apache-2.0"),
    ("libcrypto3", "3.3.2-r0", "Apache-2.0"), ("libssl3", "3.3.2-r0", "Apache-2.0"),
    ("apk-tools", "2.14.4-r0", "GPL-2.0-only"), ("scanelf", "1.3.7-r2", "GPL-2.0-only"),
    ("ssl_client", "1.36.1-r29", "GPL-2.0-only"),
]

DEB_DEBIAN = [
    ("libc6", "2.36-9", "LGPL-2.1-only"), ("libssl3", "3.0.14-1", "Apache-2.0"),
    ("zlib1g", "1.2.13-1", "Zlib"), ("libgcc-s1", "12.2.0-14", "GPL-3.0-or-later"),
    ("coreutils", "9.1-1", "GPL-3.0-or-later"), ("bash", "5.2.15-2", "GPL-3.0-or-later"),
    ("libpq5", "15.8-1", "PostgreSQL"), ("tzdata", "2024a-1", "CC0-1.0"),
]

GO_MODS = [
    ("github.com/go-chi/chi/v5", "v5.1.0", "MIT"),
    ("github.com/jackc/pgx/v5", "v5.7.1", "MIT"),
    ("github.com/danielgtaylor/huma/v2", "v2.25.0", "MIT"),
    ("golang.org/x/crypto", "v0.28.0", "BSD-3-Clause"),
    ("golang.org/x/net", "v0.30.0", "BSD-3-Clause"),
    ("github.com/CycloneDX/cyclonedx-go", "v0.9.2", "Apache-2.0"),
    ("github.com/nats-io/nats.go", "v1.37.0", "Apache-2.0"),
    ("stdlib", "go1.23.2", "BSD-3-Clause"),
]

NPM_PKGS = [
    ("solid-js", "1.9.3", "MIT"), ("@tanstack/solid-query", "5.59.16", "MIT"),
    ("vite", "5.4.10", "MIT"), ("tailwindcss", "4.0.0", "MIT"),
    ("lucide-solid", "0.454.0", "ISC"), ("@solidjs/router", "0.15.1", "MIT"),
]


def licensed(lic):
    """An SPDX id when it is one, a name when it is an expression."""
    return [{"license": {"id": lic}}] if " " not in lic else [{"license": {"name": lic}}]


def apk_component(name, version, lic, distro):
    return {"type": "library", "name": name, "version": version,
            "purl": f"pkg:apk/alpine/{name}@{version}?arch=x86_64&distro={distro}",
            "licenses": licensed(lic)}


def deb_component(name, version, lic, distro):
    return {"type": "library", "name": name, "version": version,
            "purl": f"pkg:deb/debian/{name}@{version}?arch=amd64&distro={distro}",
            "licenses": licensed(lic)}


def go_component(mod, version, lic):
    return {"type": "library", "name": mod, "version": version,
            "purl": f"pkg:golang/{mod}@{version}", "licenses": licensed(lic)}


def npm_component(name, version, lic):
    return {"type": "library", "name": name, "version": version,
            "purl": f"pkg:npm/{name}@{version}", "licenses": licensed(lic)}


# Dependency edges, keyed on package name rather than purl so a release's
# version drift cannot invalidate them. Read "A pulls in B".
#
# The shape is chosen to make the tree view worth looking at rather than to be
# accurate about any real image. Three cases have to be visible on the rig or
# the views that read this graph cannot be verified in a browser:
#
#   * a branch that reaches a vulnerable leaf   -- apk-tools -> openssl (CRITICAL)
#   * a branch that reaches none                -- ca-certificates-bundle, tzdata,
#                                                  cyclonedx-go, vite
#   * a finding that is transitive only         -- libssl3, x/net, x/crypto and
#                                                  stdlib are never direct
#                                                  dependencies of the image
#
# zlib and zlib1g are deliberately left hanging off the image rather than off a
# parent, so the direct half of the direct/transitive split is not empty on
# every artifact in the corpus.
#
# libssl3 appears in both the apk and deb sets with different dependencies, so
# its entry lists both; the ones absent from a given SBOM filter themselves out.
DEPENDS_ON = {
    # alpine
    "busybox": ["musl", "ssl_client"],
    "apk-tools": ["scanelf", "openssl"],
    "openssl": ["libssl3", "libcrypto3"],
    "ssl_client": ["libssl3"],
    "libssl3": ["libcrypto3", "libc6"],
    "libcrypto3": ["musl"],
    "zlib": ["musl"],
    "scanelf": ["musl"],
    # debian
    "bash": ["libc6"],
    "coreutils": ["libc6", "libgcc-s1"],
    "libpq5": ["libssl3"],
    "zlib1g": ["libc6"],
    "libgcc-s1": ["libc6"],
    # go
    "github.com/go-chi/chi/v5": ["golang.org/x/net"],
    "github.com/danielgtaylor/huma/v2": ["golang.org/x/net"],
    "github.com/jackc/pgx/v5": ["golang.org/x/crypto", "stdlib"],
    "github.com/nats-io/nats.go": ["golang.org/x/crypto"],
    "golang.org/x/net": ["stdlib"],
    "golang.org/x/crypto": ["stdlib"],
    # npm
    "@tanstack/solid-query": ["solid-js"],
    "@solidjs/router": ["solid-js"],
    "lucide-solid": ["solid-js"],
}


def dependency_graph(root_ref, components):
    """The CycloneDX `dependencies` array for one document.

    Without this the ingest writes no `dependency` rows, /dependencies comes
    back with no edges, and PackagesTab silently falls back to list mode -- so
    the tree, the vulnerable-only filter and the direct/transitive split are all
    unverifiable on the rig.

    `roots` additionally needs an entry whose ref is metadata.component's
    bom-ref (internal/service/search_sbom.go anchors on it), which is why the
    first entry below is the image itself.
    """
    by_name = {c["name"]: c["bom-ref"] for c in components}

    edges = []
    pulled = set()
    for c in components:
        targets = [by_name[t] for t in DEPENDS_ON.get(c["name"], []) if t in by_name]
        if targets:
            edges.append({"ref": c["bom-ref"], "dependsOn": targets})
            pulled.update(targets)

    # Whatever nothing else pulls in hangs off the image. drift() removes the
    # tail of a component list per release, so a hardcoded direct set would
    # strand its children; deriving it keeps every component reachable in
    # every release.
    direct = [c["bom-ref"] for c in components if c["bom-ref"] not in pulled]

    return [{"ref": root_ref, "dependsOn": direct}] + edges


def bump(version: str) -> str:
    """Nudges the last numeric run, so consecutive releases differ."""
    head, _, tail = version.rpartition(".")
    digits = "".join(c for c in tail if c.isdigit())
    if not head or not digits:
        return version
    return f"{head}.{int(digits) + 1}{tail[len(digits):]}"


def build_sbom(image, tag, arch, os_name, os_version, components):
    """A CycloneDX 1.6 document in the shape syft emits for a container.

    The OS properties are what ADR-020's layer-1 flavor detector reads, so the
    seeded artifacts land on real flavors (alpine-3.20, debian-12) instead of
    all collapsing to "unknown" and making the flavor axis untestable.
    """
    props = []
    if os_name:
        props += [{"name": "syft:distro:id", "value": os_name},
                  {"name": "syft:distro:version-id", "value": os_version}]
    props.append({"name": "syft:image:labels:org.opencontainers.image.architecture",
                  "value": arch})
    serial = hashlib.md5(f"{image}{tag}{arch}".encode()).hexdigest()

    # A component's purl is its bom-ref, which is what syft emits and what the
    # dependency graph is expressed in. It has to be set here rather than in
    # the per-ecosystem builders, because drift() rewrites the purl for a
    # release and the ref must follow it.
    components = [dict(c, **{"bom-ref": c["purl"]}) for c in components]
    root_ref = f"{image}:{tag}"

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-4{serial[13:16]}-8{serial[17:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {"component": {"type": "container", "bom-ref": root_ref,
                                   "name": image, "version": tag,
                                   "properties": props}},
        "components": components,
        "dependencies": dependency_graph(root_ref, components),
    }


def drift(base, rel):
    """Release `rel` of a component set: bump the first `rel`, drop a tail.

    Versions have to move between releases or /diff, the changelog and the
    version history all render an empty result and verify nothing.
    """
    out = []
    for i, c in enumerate(base):
        c = dict(c)
        if i < rel:
            new = bump(c["version"])
            c["purl"] = c["purl"].replace(c["version"], new, 1)
            c["version"] = new
        out.append(c)
    return out[: len(out) - (rel // 2)]


def built(days_ago: int) -> str:
    """RFC3339 build date. Required for container SBOMs, and the axis version
    history and the changelog order by, so releases must not all share one."""
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def corpus():
    """The artifacts to seed, oldest release first."""
    alpine = [apk_component(*p, "3.20") for p in APK_ALPINE]
    debian = [deb_component(*p, "12") for p in DEB_DEBIAN]
    gomods = [go_component(*p) for p in GO_MODS]
    npms = [npm_component(*p) for p in NPM_PKGS]

    items = []
    for rel, tag in enumerate(["v1.4.0", "v1.5.0", "v1.6.0"]):
        for arch in (["amd64", "arm64"] if tag == "v1.6.0" else ["amd64"]):
            items.append(dict(ns="local", image="ghcr.io/pfenerty/ocidex-api", tag=tag,
                              arch=arch, os=("alpine", "3.20"), built=built(120 - rel * 40),
                              components=drift(alpine, rel) + drift(gomods, rel)))
    for rel, tag in enumerate(["v1.5.0", "v1.6.0"]):
        items.append(dict(ns="local", image="ghcr.io/pfenerty/ocidex-web", tag=tag,
                          arch="amd64", os=("alpine", "3.20"), built=built(80 - rel * 40),
                          components=drift(alpine, rel) + drift(npms, rel)))
    for rel, tag in enumerate(["16.4", "17.2"]):
        items.append(dict(ns="local", image="docker.io/library/postgres", tag=tag,
                          arch="amd64", os=("debian", "12"), built=built(200 - rel * 90),
                          components=drift(debian, rel)))
    # No OS metadata and no apk/deb purls: exercises the flavor detector's
    # fallthrough to "unknown", which a distroless image really does hit.
    items.append(dict(ns="local", image="quay.io/prometheus/node-exporter", tag="v1.8.2",
                      arch="amd64", os=(None, None), built=built(15), components=gomods[:4]))
    # Private namespace, so visibility filtering has something to filter.
    items.append(dict(ns="private-lab", image="ghcr.io/acme/internal-billing", tag="v2.1.0",
                      arch="amd64", os=("debian", "12"), built=built(5),
                      components=debian + gomods[:3]))
    # devoutsider's tenant. It has to hold real rows: against an *empty*
    # namespace a cross-tenant 404 is indistinguishable from "nothing there",
    # so the denial test (ocidex-r6lu.5) would pass even if the filter were
    # removed entirely.
    for rel, tag in enumerate(["v3.0.0", "v3.1.0"]):
        items.append(dict(ns=OUTSIDER_NS, by="outsider",
                          image="ghcr.io/contoso/outsider-svc", tag=tag,
                          arch="amd64", os=("alpine", "3.20"), built=built(30 - rel * 20),
                          components=drift(alpine, rel) + drift(gomods, rel)))
    return items


# Keyed to purls the corpus above actually contains, so the findings join
# produces rows instead of a plausible-looking but empty vulnerability page.
VULNS = [
    ("CVE-2024-5535", "CRITICAL", 9.1, "openssl: SSL_select_next_proto buffer overread",
     ["pkg:apk/alpine/openssl@3.3.2-r0?arch=x86_64&distro=3.20",
      "pkg:apk/alpine/libssl3@3.3.2-r0?arch=x86_64&distro=3.20"], "3.3.2-r1"),
    ("GHSA-w32m-9786-jp63", "HIGH", 7.5, "golang.org/x/net: HTTP/2 CONTINUATION flood",
     ["pkg:golang/golang.org/x/net@v0.30.0"], "v0.31.0"),
    ("CVE-2024-45337", "HIGH", 8.2, "golang.org/x/crypto: misuse of ServerConfig.PublicKeyCallback",
     ["pkg:golang/golang.org/x/crypto@v0.28.0"], "v0.31.0"),
    ("CVE-2024-34156", "MEDIUM", 5.9, "encoding/gob: stack exhaustion in Decoder.Decode",
     ["pkg:golang/stdlib@go1.23.2"], "go1.23.3"),
    ("CVE-2023-45853", "MEDIUM", 6.5, "zlib: integer overflow in MiniZip",
     ["pkg:apk/alpine/zlib@1.3.1-r1?arch=x86_64&distro=3.20",
      "pkg:deb/debian/zlib1g@1.2.13-1?arch=amd64&distro=12"], None),
    ("CVE-2024-2961", "LOW", 3.7, "glibc: iconv buffer overflow in ISO-2022-CN-EXT",
     ["pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=12"], "2.36-10"),
]


def sql_str(s):
    return s.replace("'", "''")


def seed_vulns(db_url: str) -> None:
    """Direct SQL: there is no ingest endpoint for the vulnerability store.

    cmd/vuln-worker is its only writer and it pulls from OSV over the network,
    which is exactly the dependency a local rig has to avoid.
    """
    stmts = []
    for vid, sev, score, summary, purls, fixed in VULNS:
        s = sql_str(summary)
        raw = sql_str(json.dumps({"id": vid, "summary": summary,
                                  "database_specific": {"severity": sev}}))
        # canonical_id is not decoration. ListTopVulnerabilities opens with
        # `WHERE canonical_id != ''` (db/queries/vulnerability.sql), so a row
        # left on the column default is filtered out before anything else runs
        # and /vulnerabilities comes back empty with the rows plainly present.
        stmts.append(
            f"INSERT INTO vulnerability (id, canonical_id, summary, details, severity, cvss_score, "
            f"published_at, modified_at, raw) VALUES ('{vid}', '{vid}', '{s}', '{s}', '{sev}', {score}, "
            f"now() - interval '90 days', now() - interval '10 days', '{raw}'::jsonb) "
            f"ON CONFLICT (id) DO UPDATE SET canonical_id = EXCLUDED.canonical_id, "
            f"severity = EXCLUDED.severity, "
            f"cvss_score = EXCLUDED.cvss_score, summary = EXCLUDED.summary;")
        for purl in purls:
            fx = "NULL" if fixed is None else f"'{sql_str(fixed)}'"
            stmts.append(
                f"INSERT INTO package_vulnerability (purl, vulnerability_id, fixed_version) "
                f"VALUES ('{sql_str(purl)}', '{vid}', {fx}) "
                f"ON CONFLICT (purl, vulnerability_id) DO UPDATE "
                f"SET fixed_version = EXCLUDED.fixed_version;")
    stmts.append("UPDATE vuln_refresh_state SET last_refreshed_at = now() WHERE id;")
    # The vulnerability list reads affected counts from vuln_rollup, never from
    # joining package_vulnerability to component directly -- that join was the
    # million-row index scan ocidex-ckv.2 removed. So an unrefreshed rollup is
    # not a stale count, it is a missing row: the read query INNER JOINs it, and
    # a canonical id with no rollup row does not appear at all.
    #
    # In the deployed service internal/repository/rollup_refresh.go rebuilds
    # this on a poller. The rig cannot wait on a poller and still be a
    # one-command seed, so it runs the same aggregate here. The SELECT below is
    # vulnRollupAggregate verbatim; if that constant changes, this changes with
    # it -- the two already carry that obligation between rollup_refresh.go and
    # the seeding INSERTs in 00051_list_rollups.sql.
    stmts.append("""
DELETE FROM vuln_rollup;
INSERT INTO vuln_rollup (canonical_id, namespace_id, sbom_count, purls)
SELECT v.canonical_id, s.namespace_id,
       count(DISTINCT comp.sbom_id)::bigint AS sbom_count,
       array_agg(DISTINCT pv.purl)::text[] AS purls
FROM vulnerability v
JOIN package_vulnerability pv ON pv.vulnerability_id = v.id
JOIN component comp ON comp.purl = pv.purl
JOIN sbom s ON s.id = comp.sbom_id
WHERE v.canonical_id <> '' AND comp.purl IS NOT NULL
GROUP BY v.canonical_id, s.namespace_id;
""")
    psql(db_url, "\n".join(stmts))
    log(f"seeded {len(VULNS)} vulnerabilities")


# The rig runs no enrichment workers -- they are separate binaries, and two of
# them (git, provenance) reach out over the network, which is the dependency a
# local rig exists to avoid. So the fixture writes the rows those workers would
# have written.
#
# This is not cosmetic. GET /api/v1/artifacts defaults to `sufficient=true`
# (internal/api/search.go), and an SBOM is "sufficient" only once some
# successful enrichment carries both imageVersion and architecture
# (00013_enrichment_sufficiency.sql). Without these rows the artifacts list,
# the dashboard artifact count and every rollup built on them come back empty
# while the database plainly holds the data -- which is exactly the false
# negative that made the un-seeded rig so confusing to work against.
#
# Provenance is spread across all five ADR-037 statuses on purpose, including
# a drift *within* ocidex-api (v1.4.0 verification_failed -> v1.6.0 verified),
# because the drift feeds have nothing to show if every release agrees.
PROVENANCE = {
    ("ghcr.io/pfenerty/ocidex-api", "v1.6.0"): {"signaturePresent": True, "verified": True,
                                                "signerIdentity": "https://github.com/pfenerty/ocidex/.github/workflows/release.yml@refs/heads/main",
                                                "signerIssuer": "https://token.actions.githubusercontent.com"},
    ("ghcr.io/pfenerty/ocidex-api", "v1.5.0"): {"signaturePresent": True},
    # Carries a verificationError so the ProvenanceCard "Reason" field (ocidex-j9qa)
    # has something to render; without it the failure is a bare verdict again.
    ("ghcr.io/pfenerty/ocidex-api", "v1.4.0"): {"signaturePresent": True, "verified": False,
                                                "verificationError": "signature: none of the expected identities matched what was in the certificate, got subjects [https://github.com/pfenerty/ocidex/.github/workflows/staging.yml@refs/heads/main] with issuer https://token.actions.githubusercontent.com"},
    ("docker.io/library/postgres", "16.4"): {"artifactMissing": True},
    ("docker.io/library/postgres", "17.2"): {"attestationPresent": True},
    ("ghcr.io/acme/internal-billing", "v2.1.0"): {"signaturePresent": True, "verified": True,
                                                  "signerFingerprint": "SHA256:c9f1a4e2b7"},
}

# Left unenriched on purpose: `?sufficient=false` and the "not yet enriched"
# state need at least one artifact that is genuinely in it.
UNENRICHED = "quay.io/prometheus/node-exporter"


def seed_enrichment(db_url, items, digests):
    stmts = []
    for item in items:
        image, tag, arch = item["image"], item["tag"], item["arch"]
        if image == UNENRICHED:
            continue
        dig = digests[(image, tag, arch)][0]
        oci = sql_str(json.dumps({"imageVersion": tag, "architecture": arch,
                                  "buildDate": item["built"], "source": "fixture"}))
        stmts.append(
            f"INSERT INTO enrichment (sbom_id, enricher_name, status, data) "
            f"SELECT id, 'oci-metadata', 'success', '{oci}'::jsonb FROM sbom "
            f"WHERE digest = '{dig}' ON CONFLICT (sbom_id, enricher_name) DO UPDATE "
            f"SET status = 'success', data = EXCLUDED.data;")
        prov = PROVENANCE.get((image, tag))
        if prov is not None:
            pj = sql_str(json.dumps(prov))
            stmts.append(
                f"INSERT INTO enrichment (sbom_id, enricher_name, status, data) "
                f"SELECT id, 'provenance', 'success', '{pj}'::jsonb FROM sbom "
                f"WHERE digest = '{dig}' ON CONFLICT (sbom_id, enricher_name) DO UPDATE "
                f"SET status = 'success', data = EXCLUDED.data;")
        stmts.append(f"UPDATE sbom SET enrichment_sufficient = true WHERE digest = '{dig}';")
    psql(db_url, "\n".join(stmts))
    log(f"marked {len(items) - 1} SBOMs enriched")


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------

def ensure_namespace(api, name, visibility):
    status, body = api.get(f"/api/v1/namespaces/by-name/{name}")
    if status == 200:
        if body.get("visibility") != visibility:
            api.patch(f"/api/v1/namespaces/{body['id']}", {"visibility": visibility})
            log(f"namespace {name} -> {visibility}")
        return body["id"]
    status, body = api.post("/api/v1/namespaces", {"name": name, "visibility": visibility})
    if status not in (200, 201):
        die(f"create namespace {name}: {status} {body}")
    log(f"created namespace {name} ({visibility})")
    return body["id"]


def ensure_source(api, ns_id, ns_name, name):
    status, body = api.get("/api/v1/sources")
    for s in ((body or {}).get("data") or []) if status == 200 else []:
        if s.get("name") == name and s.get("namespace_id") == ns_id:
            return
    status, body = api.post("/api/v1/sources", {"namespace_id": ns_id, "name": name})
    if status not in (200, 201):
        die(f"create source {ns_name}/{name}: {status} {body}")
    log(f"created source {ns_name}/{name}")


def upload(api, item):
    """Uploads one SBOM. Returns (image digest, index digest)."""
    image, tag, arch = item["image"], item["tag"], item["arch"]
    dig = digest_for(image, tag, arch)
    idx = digest_for(image, tag, "index")
    bom = build_sbom(image, tag, arch, item["os"][0], item["os"][1], item["components"])
    q = (f"?source={item['ns']}/uploads&version={tag}&architecture={arch}"
         f"&digest={dig}&subject_type=container&subject_name={image}"
         f"&build_date={item['built']}")
    status, body = api.post("/api/v1/sboms" + q, json.dumps(bom).encode(),
                            "application/octet-stream")
    if status not in (200, 201, 409):
        die(f"upload {image}:{tag} ({arch}): {status} {body}")
    return dig, idx


def link_index_digests(db_url, pairs):
    """Sets sbom.index_digest for the multi-arch images.

    ADR-044's second match tier joins a workload's imageID onto index_digest,
    because containerd reports the *index* digest for a multi-arch image. The
    scanner populates that column; the upload endpoint has no query parameter
    for it, so the rig writes it here rather than leaving the "index" match
    state unreachable in a browser.
    """
    if not pairs:
        return
    psql(db_url, "\n".join(
        f"UPDATE sbom SET index_digest = '{idx}' WHERE digest = '{dig}';"
        for dig, idx in pairs))
    log(f"linked {len(pairs)} index digests")


def seed_cluster(api, ns_id, digests):
    """One cluster covering all three ADR-044 match states.

    All three must stay visually distinct and none may read as clean, so the
    fixture has to contain all three -- a cluster of nothing but matches would
    verify the easy third of the page.
    """
    status, body = api.get("/api/v1/clusters")
    cluster_id = None
    for c in ((body or {}).get("data") or []) if status == 200 else []:
        if c.get("name") == "dev-cluster":
            cluster_id = c["id"]
    if cluster_id is None:
        status, body = api.post("/api/v1/clusters", {
            "namespace_id": ns_id, "name": "dev-cluster",
            "description": "Seeded by scripts/dev-fixtures.py"})
        if status not in (200, 201):
            die(f"create cluster: {status} {body}")
        cluster_id = body["id"]
        log("created cluster dev-cluster")

    api_new = digests[("ghcr.io/pfenerty/ocidex-api", "v1.6.0", "amd64")][0]
    api_old = digests[("ghcr.io/pfenerty/ocidex-api", "v1.4.0", "amd64")][0]
    web_index = digests[("ghcr.io/pfenerty/ocidex-web", "v1.6.0", "amd64")][1]
    pg = digests[("docker.io/library/postgres", "17.2", "amd64")][0]

    workloads = [
        # exact: the digest is an ingested SBOM's own digest.
        dict(k8s_namespace="ocidex", workload_kind="Deployment", workload_name="ocidex-api",
             container_name="api", image_ref="ghcr.io/pfenerty/ocidex-api:v1.6.0",
             image_digest=api_new, pod_count=3),
        # index: containerd reported the multi-arch index digest, tier 2.
        dict(k8s_namespace="ocidex", workload_kind="Deployment", workload_name="ocidex-web",
             container_name="web", image_ref="ghcr.io/pfenerty/ocidex-web:v1.6.0",
             image_digest=web_index, pod_count=2),
        dict(k8s_namespace="ocidex", workload_kind="StatefulSet", workload_name="postgres",
             container_name="postgres", image_ref="docker.io/library/postgres:17.2",
             image_digest=pg, pod_count=1),
        # Two releases behind what the artifact tracks: drift, not a gap.
        dict(k8s_namespace="staging", workload_kind="Deployment", workload_name="ocidex-api",
             container_name="api", image_ref="ghcr.io/pfenerty/ocidex-api:v1.4.0",
             image_digest=api_old, pod_count=1),
        # unknown: a well-formed digest with no ingested SBOM behind it.
        dict(k8s_namespace="kube-system", workload_kind="DaemonSet", workload_name="cilium",
             container_name="cilium-agent", image_ref="quay.io/cilium/cilium:v1.16.3",
             image_digest=digest_for("cilium", "v1.16.3"), pod_count=5),
        dict(k8s_namespace="kube-system", workload_kind="Deployment", workload_name="coredns",
             container_name="coredns", image_ref="registry.k8s.io/coredns/coredns:v1.11.3",
             image_digest=digest_for("coredns", "v1.11.3"), pod_count=2),
        # Deliberately long, so the coverage tile's sub-line and the mobile
        # card-stack are put under the load they are meant to survive
        # (ocidex-ag4q.58, .50). A registry path this long is ordinary on GKE.
        dict(k8s_namespace="observability", workload_kind="StatefulSet",
             workload_name="kube-prometheus-stack-grafana-agent-operator",
             container_name="grafana-agent-operator-with-a-long-container-name",
             image_ref="europe-west4-docker.pkg.dev/acme-platform-prod/observability-images/"
                       "kube-prometheus-stack/grafana-agent-operator:v0.42.0-rc.3",
             image_digest=digest_for("grafana-agent-operator", "v0.42.0"), pod_count=1),
        # unresolvable: no digest at all -- an agent or runtime gap, and the
        # state most easily mistaken for "fine" if it is not styled apart.
        dict(k8s_namespace="default", workload_kind="Deployment", workload_name="legacy-adapter",
             container_name="adapter",
             image_ref="internal-registry.acme.corp/legacy/adapter:latest", pod_count=2),
        dict(k8s_namespace="default", workload_kind="CronJob", workload_name="nightly-export",
             container_name="export",
             image_ref="internal-registry.acme.corp/legacy/export:2024-11", pod_count=1),
    ]
    status, body = api.post(f"/api/v1/clusters/{cluster_id}/inventory", {"workloads": workloads})
    if status not in (200, 201):
        die(f"push inventory: {status} {body}")
    log(f"pushed {len(workloads)} workloads to dev-cluster")


def main() -> None:
    ap = argparse.ArgumentParser(description="Seed the local dev-auth rig.")
    ap.add_argument("--base-url", default=os.environ.get("OCIDEX_BASE_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--api-key")
    # No env fallback for these two. The Makefile does `include .env` + `export`,
    # so any target that shells out here carries the *deployment* DATABASE_URL
    # (:5432) in the environment, which is not this rig's database (:5433) and
    # in the worst case is somebody's real one. The rig's own dev-auth.env is
    # the authority; an explicit flag is the only way to override it.
    ap.add_argument("--db-url")
    args = ap.parse_args()

    env = load_env()
    db_url = args.db_url or env.get("DATABASE_URL") or die("no DATABASE_URL")

    # Each tenant seeds its own rows with its own key, through the ordinary
    # ownership rules. Seeding both sides as one superuser would leave the
    # corpus reachable in ways a real caller's would not be, which is the whole
    # thing the persona rig exists to stop.
    owner_key = (args.api_key or env.get("OCIDEX_DEV_KEY_DEVOWNER_RW")
                 or env.get("OCIDEX_DEV_API_KEY") or die("no API key"))
    outsider_key = env.get("OCIDEX_DEV_KEY_DEVOUTSIDER_RW") or owner_key
    api = API(args.base_url, owner_key)
    outsider_api = API(args.base_url, outsider_key)

    status, _ = api.get("/api/v1/namespaces")
    if status == 401:
        die("API rejected the rig's key -- try `make dev-auth-reset && make dev-auth-up`")

    public_ns = ensure_namespace(api, "local", "public")
    private_ns = ensure_namespace(api, "private-lab", "private")
    outsider_ns = ensure_namespace(outsider_api, OUTSIDER_NS, "private")
    ensure_source(api, public_ns, "local", "uploads")
    ensure_source(api, private_ns, "private-lab", "uploads")
    ensure_source(outsider_api, outsider_ns, OUTSIDER_NS, "uploads")

    digests = {}
    index_pairs = []
    items = corpus()
    for item in items:
        dig, idx = upload(outsider_api if item.get("by") == "outsider" else api, item)
        digests[(item["image"], item["tag"], item["arch"])] = (dig, idx)
        if item["image"] == "ghcr.io/pfenerty/ocidex-web":
            index_pairs.append((dig, idx))
    log(f"uploaded {len(digests)} SBOMs")

    link_index_digests(db_url, index_pairs)
    seed_enrichment(db_url, items, digests)
    seed_vulns(db_url)
    seed_cluster(api, public_ns, digests)
    print("\n\033[32mv\033[0m fixtures seeded -- reload :3200")


if __name__ == "__main__":
    main()
