SHELL := /bin/bash

NPM ?= npm
GO ?= go

FRONTEND_DIR := frontend
APP_NAME := vulndock-customized
CMD := ./cmd/vulndock-customized

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: install
install: frontend-install ## Install frontend dependencies.

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies from package-lock.json.
	$(NPM) ci --prefix $(FRONTEND_DIR)

.PHONY: frontend-dev
frontend-dev: ## Run Vite dev server (proxies /api to :8080).
	$(NPM) run dev --prefix $(FRONTEND_DIR)

.PHONY: frontend-build
frontend-build: ## Build the Vite frontend.
	$(NPM) run build --prefix $(FRONTEND_DIR)

.PHONY: sync-frontend-dist
sync-frontend-dist: frontend-build ## Copy frontend/dist into the Go embed tree.
	rm -rf internal/static/dist
	cp -a $(FRONTEND_DIR)/dist internal/static/dist

.PHONY: build
build: sync-frontend-dist ## Build VulnDockCustomized server binary (UI embedded).
	$(GO) build -o build/bin/$(APP_NAME) $(CMD)

.PHONY: run
run: build ## Build and run the web server on :8080.
	./build/bin/$(APP_NAME)

.PHONY: check
check: test frontend-check ## Run tests and frontend type checks.

.PHONY: test
test: go-test frontend-test ## Run backend and frontend tests.

.PHONY: frontend-check
frontend-check: ## Run Svelte/TypeScript checks.
	$(NPM) run check --prefix $(FRONTEND_DIR)

.PHONY: frontend-test
frontend-test: ## Run frontend unit tests.
	$(NPM) test --prefix $(FRONTEND_DIR)

.PHONY: go-test
go-test: ## Run Go tests.
	$(GO) test ./...

.PHONY: fmt
fmt: ## Format Go source files.
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## Tidy Go module files.
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove generated build artifacts.
	$(RM) -r build/bin $(FRONTEND_DIR)/dist
