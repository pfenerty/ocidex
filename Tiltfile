load('ext://restart_process', 'docker_build_with_restart')

allow_k8s_contexts('admin@ocidex-dev')
default_registry('localhost:5005')

# --- Auth secrets from .env (unified with docker-compose) -----------------
# Read repo-root .env and emit a 'ocidex-secrets' Secret consumed via
# envFrom by all three Go deployments. Override DATABASE_URL with the
# in-cluster Postgres URL regardless of what .env says.

def _parse_dotenv(contents):
    out = {}
    for raw in contents.split('\n'):
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, _, v = line.partition('=')
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
            v = v[1:-1]
        out[k.strip()] = v
    return out

env = _parse_dotenv(str(read_file('.env')))
for required in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 'SESSION_SECRET'):
    if not env.get(required):
        fail("%s must be set in .env (used by both docker-compose and Tilt)" % required)
# Credentials match .env and docker-compose (ocidex:ocidex) on purpose: postgres
# is port-forwarded to host 5432 below, so host-side `make migrate-up`, `make
# seed`, and psql all authenticate against the in-cluster database without a
# second set of credentials to remember.
#
# POSTGRES_PASSWORD is deliberately NOT put in this Secret. Tilt scrubs every
# Secret value out of its own logs, and this value is the bare string "ocidex" —
# a substring of every image, resource, and pod name in the stack. Including it
# turns the entire Tilt log into
# "[redacted secret ocidex-secrets:POSTGRES_PASSWORD]-api-576574dd4c-xmd89".
# tilt/postgres.yaml repeats the literal instead, exactly as docker-compose.yml
# already does.
env['DATABASE_URL'] = 'postgres://ocidex:ocidex@postgres:5432/ocidex?sslmode=disable'

def _secret_yaml(name, data):
    lines = [
        'apiVersion: v1',
        'kind: Secret',
        'metadata:',
        '  name: ' + name,
        'type: Opaque',
        'stringData:',
    ]
    for k in sorted(data.keys()):
        v = data[k].replace('\\', '\\\\').replace('"', '\\"')
        lines.append('  %s: "%s"' % (k, v))
    return '\n'.join(lines) + '\n'

k8s_yaml(blob(_secret_yaml('ocidex-secrets', env)))

# --- App stack ------------------------------------------------------------
# Per-service images. Every target copies from the single build-all stage, so
# BuildKit compiles the Go tree once and reuses it across all of them.
# api/ and pkg/ are in `only` because build-all also links cmd/operator, which
# imports api/v1alpha1 and pkg/client — without them the shared stage fails to
# compile even though no Tilt-built service needs them directly.
_build_ctx = {
    'context': '.',
    'dockerfile': 'docker/Dockerfile',
    'only': ['api/', 'cmd/', 'internal/', 'pkg/', 'go.mod', 'go.sum', 'db/'],
    'ignore': ['**/*_test.go', 'tests/'],
}
docker_build('ocidex-api',                  target='api',                  **_build_ctx)
docker_build('ocidex-scanner-worker',       target='scanner-worker',       **_build_ctx)

# One per entry in charts/ocidex values.enricherWorkers — the chart renders a
# Deployment for each, so every one needs an image in the local registry.
docker_build('ocidex-oci-metadata-worker',  target='oci-metadata-worker',  **_build_ctx)
docker_build('ocidex-git-worker',           target='git-worker',           **_build_ctx)
docker_build('ocidex-user-enricher-worker', target='user-enricher-worker', **_build_ctx)
docker_build('ocidex-provenance-worker',    target='provenance-worker',    **_build_ctx)

# Not an enricher: singleton OSV.dev refresher, but the chart deploys it by default.
docker_build('ocidex-vuln-worker',          target='vuln-worker',          **_build_ctx)

# Web image (nginx + built SPA, static assets only). Built so the in-cluster
# ocidex-web Deployment has an image to pull. The Vite local_resource below
# still serves HMR on http://localhost:3000 for day-to-day frontend work.
docker_build(
    'ocidex-web',
    context='.',
    dockerfile='docker/web/Dockerfile',
    only=['web/'],
    ignore=['web/dist', 'web/node_modules'],
)

k8s_yaml(helm('./charts/ocidex', name='ocidex', namespace='default', values=['tilt/values-dev.yaml']))

# Dev-only Postgres. charts/ocidex deliberately renders no database (ADR-031 —
# production uses a CloudNativePG Cluster owned by the homelab Flux repo), so
# the dev loop supplies its own here.
k8s_yaml('tilt/postgres.yaml')

# Schema. tilt/values-dev.yaml sets migrate.enabled=true, so the chart's
# pre-install hook Job renders as a plain Job named for the (always 1) release
# revision under `helm template`. Tilt injects the locally built ocidex-api
# image into it just like any other manifest.
_migrate = 'ocidex-migrate-1'

# Everything that talks to Postgres waits for the schema; everything that talks
# to NATS waits for the server. Without this a cold `tilt up` still converges,
# but only after a round of crash-loop backoff on every Go pod.
_db_and_nats = [_migrate, 'ocidex-nats']

k8s_resource('ocidex-api', port_forwards=port_forward(8080, 8080, host='0.0.0.0'), labels=['app'], resource_deps=_db_and_nats)
k8s_resource('ocidex-web', labels=['app'])
k8s_resource('ocidex-scanner-worker', labels=['workers'], resource_deps=_db_and_nats)
k8s_resource('ocidex-oci-metadata-worker', labels=['workers'], resource_deps=_db_and_nats)
k8s_resource('ocidex-git-worker', labels=['workers'], resource_deps=_db_and_nats)
k8s_resource('ocidex-user-enricher-worker', labels=['workers'], resource_deps=_db_and_nats)
k8s_resource('ocidex-provenance-worker', labels=['workers'], resource_deps=_db_and_nats)
# No NATS: the vuln worker only reaches Postgres and api.osv.dev.
k8s_resource('ocidex-vuln-worker', labels=['workers'], resource_deps=[_migrate])
k8s_resource('ocidex-nats', labels=['infra'])
k8s_resource('postgres', port_forwards=port_forward(5432, 5432, host='0.0.0.0'), labels=['infra'])
k8s_resource(_migrate, labels=['infra'], resource_deps=['postgres'])

local_resource(
    'web',
    serve_cmd='cd web && npm run dev -- --host',
    deps=['web/src', 'web/public', 'web/index.html', 'web/vite.config.ts'],
    ignore=['web/dist', 'web/node_modules'],
    labels=['app'],
    links=['http://localhost:3000'],
    resource_deps=['ocidex-api'],
)
