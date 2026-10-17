// Not a real module. Some npm packages ship Go sources (flatted does), so once
// web/node_modules exists every `./...` from the repo root would build, vet and
// test them. A go.mod here makes web/ a separate module, which root `./...`
// patterns skip, so make targets, CI and gopls all ignore it with no filtering.
// It is deliberately not listed in go.work. (ocidex-gyr0.2)
module github.com/pfenerty/ocidex/web-not-a-module

go 1.27.0
