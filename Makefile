BINARY_NAME := ocidex
BUILD_DIR := bin

# Load .env if it exists
ifneq (,$(wildcard .env))
  include .env
  export
endif

.PHONY: all build run fmt lint test test-coverage test-integration check init clean generate migrate-up migrate-down seed frontend frontend-dev frontend-init frontend-lint frontend-lint-fix openapi openapi-check tekton-synth tekton-check help

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

check: fmt lint test openapi-check ## Run fmt, lint, test, and openapi staleness check

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

tekton-synth: ## Synthesize Tekton pipeline YAML from TypeScript
	cd .tekton && npm ci && npx ts-node pipeline.ts

tekton-check: ## Verify generated Tekton YAML is up-to-date
	cd .tekton && npm ci && npx ts-node pipeline.ts
	cd .tekton && git diff --exit-code generated/ || (echo "ERROR: .tekton/generated/ is stale. Run 'make tekton-synth'." && exit 1)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
