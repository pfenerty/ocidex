BINARY_NAME := ocidex
BUILD_DIR := bin

# Load .env if it exists
ifneq (,$(wildcard .env))
  include .env
  export
endif

.PHONY: all build run fmt lint test test-coverage test-integration check init clean generate migrate-up migrate-down seed frontend frontend-dev frontend-init openapi help

all: check build ## Run all checks and build

build: ## Build the Go binary
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ocidex

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

check: fmt lint test ## Run fmt, lint, and test

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

seed: ## Seed database with real SBOMs from ubuntu:focal (20.04) images
	./scripts/seed.sh

frontend-init: ## Install frontend dependencies
	cd web && npm install

frontend: frontend-init ## Build the SolidJS frontend
	cd web && npm run build

frontend-dev: ## Start the frontend dev server (with API proxy to :8080)
	cd web && npm run dev --host

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
