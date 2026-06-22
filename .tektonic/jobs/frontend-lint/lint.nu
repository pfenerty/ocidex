#!/usr/bin/env nu
log $"pwd=(pwd) uid=(id -u) node=(node --version) npm=(npm --version)"
log $"node_modules exists=('node_modules' | path exists) package.json exists=('package.json' | path exists)"
log "Installing dependencies"
^npm ci
log $"node_modules exists after install=('node_modules' | path exists)"
if ('node_modules/.bin/eslint' | path exists) { log "eslint binary found" } else { log "WARNING: eslint binary NOT found" }
log "Running ESLint"
^npm run lint
log "OK: no lint errors"
