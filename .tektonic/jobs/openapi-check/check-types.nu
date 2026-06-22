#!/usr/bin/env nu
log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
log "Installing dependencies"
^npm ci
log $"node_modules exists after install=('node_modules' | path exists)"
log "Generating TypeScript types from spec"
^npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts
log "Diffing against committed types"
^diff src/types/openapi.d.ts /tmp/openapi-check.d.ts
log "OK: types up to date"
