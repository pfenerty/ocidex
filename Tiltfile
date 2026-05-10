load('ext://restart_process', 'docker_build_with_restart')

default_registry('localhost:5005')

docker_build(
    'ocidex',
    context='.',
    dockerfile='docker/api/Dockerfile',
    only=['cmd/', 'internal/', 'go.mod', 'go.sum', 'db/'],
    ignore=['**/*_test.go', 'tests/'],
)

k8s_yaml(kustomize('k8s/overlays/dev'))

k8s_resource('ocidex-api', port_forwards='8080:8080', labels=['app'])
k8s_resource('ocidex-scanner-worker', labels=['workers'])
k8s_resource('ocidex-enrichment-worker', labels=['workers'])
k8s_resource('nats', labels=['infra'])
k8s_resource('postgres', port_forwards='5432:5432', labels=['infra'])

local_resource(
    'web',
    serve_cmd='cd web && npm run dev -- --host',
    deps=['web/src', 'web/public', 'web/index.html', 'web/vite.config.ts'],
    ignore=['web/dist', 'web/node_modules'],
    labels=['app'],
    links=['http://localhost:3000'],
    resource_deps=['ocidex-api'],
)
