# TacLab — developer targets (AGENTS.md §5)

export PATH := $(HOME)/.local/go/bin:/usr/local/go/bin:$(HOME)/.local/node-v22.14.0-linux-x64/bin:$(PATH)

MODULE      ?= github.com/hilather/go-lab-tacacs-mcp
BIN_DIR     ?= bin
DIST_DIR    ?= dist
BINARY      ?= taclabd
GO          ?= go
GOFLAGS     ?=
GO_TESTFLAGS ?= -count=1
CMD_PKG     := ./cmd/taclabd
GOSRC       := cmd internal tools
GOPKGS       = $(shell $(GO) list ./... | grep -v '/node_modules/')

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDTIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOVER     := $(shell $(GO) version 2>/dev/null | awk '{print $$3}')
UI_VERSION ?= 0.0.0
LDFLAGS   := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILDTIME) -X main.uiVersion=$(UI_VERSION)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make test             go test ./..."
	@echo "  make test-race        go test -race ./..."
	@echo "  make vet              go vet ./..."
	@echo "  make fmt              gofmt -w"
	@echo "  make lint             gofmt check + go vet (+ staticcheck if installed)"
	@echo "  make fuzz-smoke       fuzz seed corpus as unit tests"
	@echo "  make bench            header, body, and 64B/1KiB obfuscate benches under internal/tacacs (not credentials KDF)"
	@echo "  make web-install      npm ci in web/"
	@echo "  make web-test         npm test (Vitest component suite)"
	@echo "  make web-typecheck    tsc --noEmit"
	@echo "  make web-lint         eslint"
	@echo "  make web-build        production Vite build + copy into internal/ui/dist"
	@echo "  make web-e2e          Playwright keyboard/session smoke"
	@echo "  make generate         regenerate checked-in generated files"
	@echo "  make check-registries validate conformance and operation registries (includes 1.0 -release gate)"
	@echo "  make check-generated  fail on generated-file drift"
	@echo "  make secrets          secret scan"
	@echo "  make vuln             govulncheck"
	@echo "  make docs-check       README link policy"
	@echo "  make check-hooks      prove format/type/drift/secret hooks fail closed"
	@echo "  make ci               lint + tests + web + secrets + registries + drift + hooks + release-notes self-test + build"
	@echo "  make build            build $(BIN_DIR)/$(BINARY)"
	@echo "  make image            docker build default (distroless) ghcr.io/hilather/go-lab-tacacs-mcp:\$(VERSION)"
	@echo "  make image-ubuntu     Ubuntu 24.04 runtime tag :\$(VERSION)-ubuntu"
	@echo "  make image-rocky      Rocky Linux 9 runtime tag :\$(VERSION)-rocky"
	@echo "  make image-variants   distroless + ubuntu + rocky"
	@echo "  make release-notes    CHANGELOG + git log -> dist/RELEASE_NOTES.md"
	@echo "  make lab-gen          generate secrets/certs into deployments/compose"
	@echo "  make lab-test         build image, generate ephemeral lab, run LAB-*"
	@echo "  make cisco-lab        optional Containerlab+IOL lab (skip 0 if image/clab absent)"
	@echo "  make clean            remove bin/ and dist/"

.PHONY: test
test:
	$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) $(GOPKGS)

.PHONY: test-race
test-race:
	$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) -race $(GOPKGS)

.PHONY: vet
vet:
	$(GO) vet $(GOFLAGS) $(GOPKGS)

.PHONY: fmt
fmt:
	gofmt -w $(GOSRC)
	@echo "gofmt -w complete"

.PHONY: lint
lint:
	@unformatted=$$(gofmt -l $(GOSRC)); \
	if [ -n "$$unformatted" ]; then \
		echo "ERROR: gofmt needed on the following files:"; \
		echo "$$unformatted"; \
		echo "Fix: make fmt"; \
		exit 1; \
	fi
	$(GO) vet $(GOFLAGS) $(GOPKGS)
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck $(GOPKGS); \
	else \
		echo "staticcheck not installed; skipped (CI installs it)"; \
	fi

.PHONY: fuzz-smoke
fuzz-smoke:
	$(GO) test $(GOFLAGS) ./internal/tacacs/... ./internal/domain ./internal/config ./internal/credentials ./internal/events ./internal/api/operations -run 'Fuzz'

.PHONY: bench
bench:
	@chmod +x tools/bench.sh
	./tools/bench.sh

.PHONY: web-install
web-install:
	npm --prefix web ci

.PHONY: web-test
web-test:
	npm --prefix web test

.PHONY: web-typecheck
web-typecheck:
	npm --prefix web run typecheck

.PHONY: web-lint
web-lint:
	npm --prefix web run lint

.PHONY: web-build
web-build:
	npm --prefix web run build
	$(MAKE) web-embed

.PHONY: web-embed
web-embed:
	@mkdir -p internal/ui/dist
	@rm -rf internal/ui/dist/assets
	@if [ -d web/dist ]; then cp -a web/dist/. internal/ui/dist/; fi
	@echo "copied web/dist -> internal/ui/dist"

.PHONY: web-e2e
web-e2e:
	npx --prefix web playwright install chromium
	npm --prefix web run test:e2e

.PHONY: generate
generate:
	$(GO) run ./tools/generate
	$(GO) run ./tools/check-registries -write-docs -release

.PHONY: check-registries
check-registries:
	$(GO) run ./tools/check-registries -release

.PHONY: check-generated
check-generated:
	@chmod +x tools/check-generated.sh
	./tools/check-generated.sh

.PHONY: secrets
secrets:
	@chmod +x tools/check-secrets.sh
	./tools/check-secrets.sh

.PHONY: vuln
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: docs-check
docs-check:
	@chmod +x tools/check-docs.sh tools/check-pages-workflow.sh
	./tools/check-docs.sh
	./tools/check-pages-workflow.sh

.PHONY: check-hooks
check-hooks:
	@chmod +x tools/check-hooks.sh
	./tools/check-hooks.sh

.PHONY: ci
ci: lint test test-race fuzz-smoke web-install web-typecheck web-lint web-test web-build web-e2e secrets check-registries check-generated docs-check check-hooks check-release-notes build

IMAGE_NAME ?= ghcr.io/hilather/go-lab-tacacs-mcp

.PHONY: image
image:
	docker build \
		--target runtime \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILDTIME=$(BUILDTIME) \
		--build-arg UI_VERSION=$(UI_VERSION) \
		-t $(IMAGE_NAME):$(VERSION) \
		-t $(IMAGE_NAME):dev \
		.

.PHONY: image-ubuntu
image-ubuntu:
	docker build \
		--target runtime-ubuntu \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILDTIME=$(BUILDTIME) \
		--build-arg UI_VERSION=$(UI_VERSION) \
		-t $(IMAGE_NAME):$(VERSION)-ubuntu \
		.

.PHONY: image-rocky
image-rocky:
	docker build \
		--target runtime-rocky \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILDTIME=$(BUILDTIME) \
		--build-arg UI_VERSION=$(UI_VERSION) \
		-t $(IMAGE_NAME):$(VERSION)-rocky \
		.

.PHONY: image-variants
image-variants: image image-ubuntu image-rocky

.PHONY: release-notes
release-notes:
	@chmod +x tools/release-notes.sh
	./tools/release-notes.sh

.PHONY: check-release-notes
check-release-notes:
	@chmod +x tools/release-notes.sh tools/release-notes_test.sh
	./tools/release-notes_test.sh

.PHONY: lab-gen
lab-gen:
	$(GO) run ./tools/labgen -force deployments/compose

.PHONY: lab-test
lab-test:
	@chmod +x tools/lab-test.sh
	./tools/lab-test.sh

.PHONY: cisco-lab
cisco-lab:
	$(GO) run ./tools/ciscolab

.PHONY: build
build:
	@if [ -f web/dist/index.html ]; then \
		$(MAKE) web-embed; \
	elif [ ! -f internal/ui/dist/index.html ]; then \
		echo "WARNING: embedding UI stub (run make web-build for the production SPA)" >&2; \
	fi
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)
	@echo "built $(BIN_DIR)/$(BINARY) version=$(VERSION) commit=$(COMMIT) go=$(GOVER) built=$(BUILDTIME)"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) web/dist web/coverage
