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
LDFLAGS   := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILDTIME)

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make test             go test ./..."
	@echo "  make test-race        go test -race ./..."
	@echo "  make vet              go vet ./..."
	@echo "  make fmt              gofmt -w"
	@echo "  make lint             gofmt check + go vet (+ staticcheck if installed)"
	@echo "  make fuzz-smoke       fuzz seed tests (no-op until fuzz targets exist)"
	@echo "  make bench            FAIL until real benches exist; then go test -bench"
	@echo "  make web-install      npm ci in web/"
	@echo "  make web-test         npm test (placeholder suite)"
	@echo "  make web-typecheck    tsc --noEmit"
	@echo "  make web-lint         eslint"
	@echo "  make web-build        production Vite build"
	@echo "  make generate         regenerate checked-in generated files"
	@echo "  make check-generated  fail on generated-file drift"
	@echo "  make secrets          secret scan"
	@echo "  make vuln             govulncheck"
	@echo "  make docs-check       README link policy"
	@echo "  make check-hooks      prove format/type/drift/secret hooks fail closed"
	@echo "  make ci               lint + tests + web + secrets + drift + hook self-test"
	@echo "  make build            build $(BIN_DIR)/$(BINARY)"
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
	$(GO) test $(GOFLAGS) ./internal/tacacs/... -run 'Fuzz' -fuzztime=0

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

.PHONY: web-e2e
web-e2e:
	npm --prefix web run test:e2e

.PHONY: generate
generate:
	$(GO) run ./tools/generate

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
	@chmod +x tools/check-docs.sh
	./tools/check-docs.sh

.PHONY: check-hooks
check-hooks:
	@chmod +x tools/check-hooks.sh
	./tools/check-hooks.sh

.PHONY: ci
ci: lint test test-race fuzz-smoke web-typecheck web-lint web-test secrets check-generated docs-check check-hooks build

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)
	@echo "built $(BIN_DIR)/$(BINARY) version=$(VERSION) commit=$(COMMIT) go=$(GOVER) built=$(BUILDTIME)"

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) web/dist web/coverage
