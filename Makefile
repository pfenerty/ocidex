BINARY_NAME := ocidex
BUILD_DIR := bin

# Load .env if it exists
ifneq (,$(wildcard .env))
  include .env
  export
endif

.PHONY: all build run fmt lint test test-coverage test-integration check init clean generate migrate-up migrate-down seed frontend frontend-dev frontend-init frontend-lint frontend-lint-fix frontend-typecheck frontend-test openapi openapi-check tekton-synth tekton-check dev-registry dev-cluster-up dev-cluster-down dev-up dev-down help

all: check build ## Run all checks and build

build: ## Build the Go binaries
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ocidex
	go build -o $(BUILD_DIR)/scanner-worker ./cmd/scanner-worker
	go build -o $(BUILD_DIR)/enrichment-worker ./cmd/enrichment-worker

run: build ## Run the API server
	./$(BUILD_DIR)/$(BINARY_NAME)

fmt: ## Format code with gofmt
	gofmt -w -s .

lint: ## Run golangci-lint
	golangci-lint run ./...

test: ## Run unit tests
	go test -v -race -short ./...

test-coverage: ## Run tests with HTML coverage report
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

test-integration: ## Run integration tests
	go test -v -race ./tests/...

check: fmt lint test openapi-check frontend-lint frontend-typecheck frontend-test ## Run fmt, lint, test, and openapi staleness check

init: ## Download dependencies and install tools
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR) coverage.out coverage.html

generate: ## Run code generation (sqlc)
	sqlc generate

migrate-up: ## Run database migrations up
	goose -dir db/migrations postgres "$$DATABASE_URL" up

migrate-down: ## Roll back last database migration
	goose -dir db/migrations postgres "$$DATABASE_URL" down

openapi: ## Regenerate OpenAPI spec and TypeScript types
	go run ./cmd/specgen > web/openapi.json
	cd web && npm run generate-api

openapi-check: ## Verify OpenAPI spec and TypeScript types are up-to-date
	go run ./cmd/specgen > /tmp/openapi-check.json
	diff web/openapi.json /tmp/openapi-check.json || (echo "ERROR: web/openapi.json is stale. Run 'make openapi'." && exit 1)
	cd web && npx openapi-typescript openapi.json -o /tmp/openapi-check.d.ts
	diff web/src/types/openapi.d.ts /tmp/openapi-check.d.ts || (echo "ERROR: openapi.d.ts is stale. Run 'make openapi'." && exit 1)

seed: ## Seed database with real SBOMs from public OCI registries
	nu scripts/seed.nu

frontend-init: ## Install frontend dependencies
	cd web && npm install

frontend: frontend-init ## Build the SolidJS frontend
	cd web && npm run build

frontend-dev: ## Start the frontend dev server (with API proxy to :8080)
	cd web && npm run dev --host

frontend-lint: ## Run ESLint on the frontend
	cd web && npm run lint

frontend-lint-fix: ## Run ESLint with auto-fix on the frontend
	cd web && npm run lint:fix

frontend-typecheck: frontend-init ## Type-check the frontend with tsc
	cd web && npx tsc --noEmit

frontend-test: frontend-init ## Run frontend unit tests
	cd web && npm test

tekton-synth: ## Synthesize Tekton pipeline YAML from TypeScript
	cd .tektonic && npm ci && npx ts-node pipeline.ts
	printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\nresources:\n' > .tektonic/generated/kustomization.yaml
	ls -1 .tektonic/generated/*.k8s.yaml | xargs -n1 basename | sed 's/^/  - /' >> .tektonic/generated/kustomization.yaml

tekton-check: ## Verify generated Tekton YAML is up-to-date
	cd .tektonic && npm ci && npx ts-node pipeline.ts
	printf 'apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\nresources:\n' > .tektonic/generated/kustomization.yaml
	ls -1 .tektonic/generated/*.k8s.yaml | xargs -n1 basename | sed 's/^/  - /' >> .tektonic/generated/kustomization.yaml
	cd .tektonic && git diff --exit-code generated/ || (echo "ERROR: .tektonic/generated/ is stale. Run 'make tekton-synth'." && exit 1)

dev-registry: ## Start the local Docker registry used by the Talos dev cluster
	@docker inspect ocidex-dev-registry >/dev/null 2>&1 || \
	  docker run -d --restart=always -p 5005:5000 --name ocidex-dev-registry registry:2

dev-cluster-up: dev-registry ## Create local Talos dev cluster wired to the local registry
	@if [ "$$(id -u)" = "0" ]; then echo "ERROR: do not run as root — your user is in the docker group"; exit 1; fi
	@if [ ! -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then \
	  echo "ERROR: br_netfilter kernel module not loaded (required by flannel CNI)."; \
	  echo "Run: sudo modprobe br_netfilter && echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf"; \
	  exit 1; \
	fi
	talosctl cluster create docker \
	  --name ocidex-dev \
	  --workers 1 \
	  --config-patch @tilt/talos-cluster.yaml \
	  || echo "talosctl exited non-zero (likely CoreDNS bootstrap timeout); proceeding..."
	talosctl --context ocidex-dev --nodes 10.5.0.2 kubeconfig --force --force-context-name admin@ocidex-dev
	kubectl --context admin@ocidex-dev wait --for=condition=Ready nodes --all --timeout=180s
	kubectl --context admin@ocidex-dev wait --for=condition=Ready pods --all -n kube-system --timeout=180s

dev-cluster-down: ## Destroy local Talos dev cluster and its registry
	talosctl --name ocidex-dev cluster destroy --force 2>/dev/null || true
	rm -rf $(HOME)/.talos/clusters/ocidex-dev
	docker rm -f ocidex-dev-controlplane-1 ocidex-dev-worker-1 ocidex-dev-registry 2>/dev/null || true
	docker network rm ocidex-dev 2>/dev/null || true
	@# Prune stale talos/kube context entries so the next dev-cluster-up isn't auto-renamed (ocidex-dev-2, etc).
	@for ctx in $$(talosctl config contexts 2>/dev/null | awk 'NR>1 {n = ($$1 == "*") ? $$2 : $$1; if (n ~ /^ocidex-dev(-[0-9]+)?$$/) print n}'); do \
	  talosctl config remove "$$ctx" -y >/dev/null 2>&1 || true; \
	done
	@for ctx in $$(kubectl config get-contexts -o name 2>/dev/null | grep -E '^admin@ocidex-dev(-[0-9]+)?$$'); do \
	  kubectl config delete-context "$$ctx" >/dev/null 2>&1 || true; \
	done
	@for c in $$(kubectl config get-clusters 2>/dev/null | grep -E '^ocidex-dev(-[0-9]+)?$$'); do \
	  kubectl config delete-cluster "$$c" >/dev/null 2>&1 || true; \
	done
	@for u in $$(kubectl config get-users 2>/dev/null | grep -E '^admin@ocidex-dev(-[0-9]+)?$$'); do \
	  kubectl config delete-user "$$u" >/dev/null 2>&1 || true; \
	done

dev-up: ## Build, deploy, and watch ocidex on the local Talos cluster (Tilt)
	@command -v tilt >/dev/null || { echo "tilt not on PATH — run inside 'flox activate'"; exit 1; }
	@# A suspended make dev-up (Ctrl-Z) or an orphan daemon from a prior session keeps port 10350 bound.
	@if pgrep -x tilt >/dev/null 2>&1; then \
	  echo "stopping existing tilt process(es): $$(pgrep -x tilt | tr '\n' ' ')"; \
	  pkill -x tilt 2>/dev/null || true; \
	  for i in 1 2 3 4 5; do pgrep -x tilt >/dev/null 2>&1 || break; sleep 1; done; \
	  if pgrep -x tilt >/dev/null 2>&1; then \
	    echo "tilt still running after SIGTERM, sending SIGKILL"; \
	    pkill -9 -x tilt 2>/dev/null || true; sleep 1; \
	  fi; \
	fi
	tilt up

dev-down: ## Stop Tilt and remove deployed resources
	@tilt down || true
	@if pgrep -x tilt >/dev/null 2>&1; then \
	  echo "stopping tilt process(es): $$(pgrep -x tilt | tr '\n' ' ')"; \
	  pkill -x tilt 2>/dev/null || true; \
	  for i in 1 2 3 4 5; do pgrep -x tilt >/dev/null 2>&1 || break; sleep 1; done; \
	  pgrep -x tilt >/dev/null 2>&1 && pkill -9 -x tilt 2>/dev/null || true; \
	fi

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
