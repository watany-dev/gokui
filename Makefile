GO ?= go
COVERAGE_THRESHOLD ?= 95
RELEASE_CHECK_VULN ?= 1
INSPECT_SARIF_OUT ?= inspect-results.sarif
VULN_GOTOOLCHAIN ?= go1.26.3+auto
GOFMT_TARGETS := cmd internal
MAIN_PKG := ./cmd/gokui
BUILD_OUT ?= gokui
CACHE_DIR ?= $(CURDIR)/.cache
RELEASE_CHECK_BUILD_OUT ?= $(CACHE_DIR)/gokui-release-check
RELEASE_CHECK_SARIF_OUT ?= $(CACHE_DIR)/inspect-results.sarif

export GOCACHE ?= $(CACHE_DIR)/go-build
export GOMODCACHE ?= $(CACHE_DIR)/gomod
export GOPATH ?= $(CACHE_DIR)/gopath
export XDG_CACHE_HOME ?= $(CACHE_DIR)/xdg

# Reproducible-build inputs. Override on the command line for releases:
#   make build VERSION=v1.2.3 COMMIT=$(git rev-parse HEAD) DATE=$(git log -1 --format=%cI)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

.PHONY: build fmt fmt-check lint typecheck deadcode test test-race coverage vuln actionlint check release-check release-check-offline release-evidence release-evidence-offline release-evidence-online inspect-sarif

build:
	$(GO) build -trimpath -buildvcs=true -ldflags='$(LDFLAGS)' -o $(BUILD_OUT) $(MAIN_PKG)

fmt:
	$(GO) fmt ./...

fmt-check:
	files="$$(find $(GOFMT_TARGETS) -name '*.go' -print)"; \
	if [ -z "$$files" ]; then \
		exit 0; \
	fi; \
	unformatted="$$(gofmt -l $$files)"; \
	if [ -n "$$unformatted" ]; then \
		printf '%s\n' "$$unformatted"; \
		exit 1; \
	fi

lint:
	$(GO) vet ./...
	$(GO) tool staticcheck ./...

typecheck:
	$(GO) test -run '^$$' ./...

deadcode:
	$(GO) tool deadcode $(MAIN_PKG)

test:
	$(GO) test ./...

test-race:
	$(GO) test -race -shuffle=on ./...

coverage:
	COVERAGE_THRESHOLD=$(COVERAGE_THRESHOLD) bash ./scripts/check-coverage.sh

vuln:
	GOTOOLCHAIN=$(VULN_GOTOOLCHAIN) $(GO) tool govulncheck ./...

actionlint:
	$(GO) tool actionlint

check: fmt-check lint typecheck deadcode coverage

release-check: check test test-race
	@set -e; \
	assert_no_symlink_components() { \
		path="$$1"; \
		label="$$2"; \
		current="$$path"; \
		while :; do \
			if [ -L "$$current" ]; then \
				echo "$$label contains symlink path component: $$current" >&2; \
				exit 1; \
			fi; \
			parent="$$(dirname "$$current")"; \
			if [ "$$parent" = "$$current" ]; then \
				break; \
			fi; \
			current="$$parent"; \
		done; \
	}; \
	assert_no_symlink_components "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path"; \
	assert_no_symlink_components "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path"; \
	if [ "$(RELEASE_CHECK_BUILD_OUT)" = "$(RELEASE_CHECK_SARIF_OUT)" ]; then \
		echo "release-check build and SARIF outputs must be different paths" >&2; \
		exit 1; \
	fi; \
	if [ -e "$(RELEASE_CHECK_BUILD_OUT)" ]; then \
		echo "release-check build output already exists: $(RELEASE_CHECK_BUILD_OUT)" >&2; \
		exit 1; \
	fi; \
	if [ -e "$(RELEASE_CHECK_SARIF_OUT)" ]; then \
		echo "release-check SARIF output already exists: $(RELEASE_CHECK_SARIF_OUT)" >&2; \
		exit 1; \
	fi; \
	trap 'rm -f -- "$(RELEASE_CHECK_BUILD_OUT)" "$(RELEASE_CHECK_SARIF_OUT)"' EXIT; \
	$(MAKE) build BUILD_OUT=$(RELEASE_CHECK_BUILD_OUT); \
	$(MAKE) inspect-sarif INSPECT_SARIF_OUT=$(RELEASE_CHECK_SARIF_OUT); \
	if [ "$(RELEASE_CHECK_VULN)" = "1" ]; then \
		$(MAKE) vuln; \
	else \
		echo "Skipping vuln check (RELEASE_CHECK_VULN=$(RELEASE_CHECK_VULN))"; \
	fi

release-check-offline:
	$(MAKE) release-check RELEASE_CHECK_VULN=0

release-evidence:
	./scripts/new-release-evidence.sh

release-evidence-offline:
	./scripts/collect-release-evidence.sh

release-evidence-online:
	./scripts/collect-release-evidence.sh --with-vuln

inspect-sarif:
	./scripts/generate-inspect-sarif.sh "$(INSPECT_SARIF_OUT)"
