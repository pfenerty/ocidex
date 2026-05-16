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
env['DATABASE_URL'] = 'postgres://ocidex:devpass@postgres:5432/ocidex?sslmode=disable'
env['POSTGRES_PASSWORD'] = 'devpass'

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
# Per-service images. The Dockerfile is multi-target with a shared builder
# stage, so BuildKit reuses the Go compile output across all three.
_build_ctx = {
    'context': '.',
    'dockerfile': 'docker/Dockerfile',
    'only': ['cmd/', 'internal/', 'go.mod', 'go.sum', 'db/'],
    'ignore': ['**/*_test.go', 'tests/'],
}
docker_build('ocidex-api',               target='api',               **_build_ctx)
docker_build('ocidex-scanner-worker',    target='scanner-worker',    **_build_ctx)
docker_build('ocidex-enrichment-worker', target='enrichment-worker', **_build_ctx)
docker_build('ocidex-migrate',           target='migrate',           **_build_ctx)

# Web image (Caddy + built SPA). Built so the in-cluster ocidex-web Deployment
# has an image to pull. The Vite local_resource below still serves HMR on
# http://localhost:3000 for day-to-day frontend work.
docker_build(
    'ocidex-web',
    context='.',
    dockerfile='docker/web/Dockerfile',
    only=['web/'],
    ignore=['web/dist', 'web/node_modules'],
)

k8s_yaml(kustomize('k8s/overlays/dev'))

k8s_resource('ocidex-api', port_forwards=port_forward(8080, 8080, host='0.0.0.0'), labels=['app'])
k8s_resource('ocidex-web', labels=['app'])
k8s_resource('ocidex-scanner-worker', labels=['workers'])
k8s_resource('ocidex-enrichment-worker', labels=['workers'])
k8s_resource('nats', labels=['infra'])
k8s_resource('postgres', port_forwards=port_forward(5432, 5432, host='0.0.0.0'), labels=['infra'])
k8s_resource('ocidex-migrate', resource_deps=['postgres'], labels=['infra'])

local_resource(
    'web',
    serve_cmd='cd web && npm run dev -- --host',
    deps=['web/src', 'web/public', 'web/index.html', 'web/vite.config.ts'],
    ignore=['web/dist', 'web/node_modules'],
    labels=['app'],
    links=['http://localhost:3000'],
    resource_deps=['ocidex-api'],
)
