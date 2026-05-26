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
RELEASE_CHECK_BUILD_OUT_ABS := $(abspath $(RELEASE_CHECK_BUILD_OUT))
RELEASE_CHECK_SARIF_OUT_ABS := $(abspath $(RELEASE_CHECK_SARIF_OUT))
MAKEFILE_DIR_ABS := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
RELEASE_CHECK_GIT_DIR_ABS := $(MAKEFILE_DIR_ABS)/.git
RELEASE_CHECK_REPO_ROOT_ABS := $(MAKEFILE_DIR_ABS)

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

.PHONY: build fmt fmt-check lint typecheck deadcode test test-race coverage vuln actionlint check beta-check release-check-preflight release-check release-check-offline release-evidence release-evidence-offline release-evidence-online release-evidence-beta inspect-sarif

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

beta-check:
	$(MAKE) check
	$(MAKE) test
	$(MAKE) build
	$(MAKE) inspect-sarif

release-check-preflight:
	@set -e; \
	emit_preflight_error() { \
		code="$$1"; \
		message="$$2"; \
		echo "[$$code] $$message" >&2; \
		exit 1; \
	}; \
	assert_no_symlink_components() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		current="$$path"; \
		while :; do \
			if [ -L "$$current" ]; then \
				emit_preflight_error "$$code" "$$label contains symlink path component: $$current"; \
			fi; \
			parent="$$(dirname "$$current")"; \
			if [ "$$parent" = "$$current" ]; then \
				break; \
			fi; \
			current="$$parent"; \
		done; \
	}; \
	assert_not_git_path() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			"$(RELEASE_CHECK_GIT_DIR_ABS)"|"$(RELEASE_CHECK_GIT_DIR_ABS)"/*) \
				emit_preflight_error "$$code" "$$label must be a non-root file path outside .git: $$path"; \
			;; \
		esac; \
	}; \
	assert_under_repo_root() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			"$(RELEASE_CHECK_REPO_ROOT_ABS)"/*) ;; \
			*) \
				emit_preflight_error "$$code" "$$label must resolve under repository root ($(RELEASE_CHECK_REPO_ROOT_ABS)): $$path"; \
			;; \
		esac; \
	}; \
	assert_no_dot_segments() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			"."|".."|*/./*|*/../*|./*|../*|*/.|*/..) \
				emit_preflight_error "$$code" "$$label must not contain '.' or '..' path segments: $$path"; \
			;; \
		esac; \
	}; \
	assert_no_empty_segments() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			*//*) \
				emit_preflight_error "$$code" "$$label must not contain empty path segments: $$path"; \
			;; \
		esac; \
	}; \
	assert_no_surrounding_whitespace() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			" "*|*" ") \
				emit_preflight_error "$$code" "$$label must not include leading or trailing whitespace: $$path"; \
			;; \
		esac; \
	}; \
	assert_no_control_chars() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		sanitized="$$(printf '%s' "$$path" | LC_ALL=C tr -d '\000-\037\177')"; \
		if [ "$$path" != "$$sanitized" ]; then \
			emit_preflight_error "$$code" "$$label must not contain ASCII control characters"; \
		fi; \
	}; \
	assert_sarif_extension() { \
		path="$$1"; \
		label="$$2"; \
		code="$$3"; \
		case "$$path" in \
			*.sarif) ;; \
			*) \
				emit_preflight_error "$$code" "$$label must end with .sarif: $$path"; \
			;; \
		esac; \
	}; \
	case "$(RELEASE_CHECK_BUILD_OUT)" in ""|"/"|"."|*/) \
		emit_preflight_error "RC_PREFLIGHT_BUILD_OUT_INVALID" "release-check build output path must be a non-root file path"; \
	;; esac; \
	case "$(RELEASE_CHECK_SARIF_OUT)" in ""|"/"|"."|*/) \
		emit_preflight_error "RC_PREFLIGHT_SARIF_OUT_INVALID" "release-check SARIF output path must be a non-root file path"; \
	;; esac; \
	assert_no_control_chars "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_no_control_chars "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_no_surrounding_whitespace "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_no_surrounding_whitespace "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_no_empty_segments "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_no_empty_segments "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_no_dot_segments "$(RELEASE_CHECK_BUILD_OUT)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_no_dot_segments "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_sarif_extension "$(RELEASE_CHECK_SARIF_OUT)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_under_repo_root "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_under_repo_root "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_not_git_path "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_INVALID"; \
	assert_not_git_path "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_INVALID"; \
	assert_no_symlink_components "$(RELEASE_CHECK_BUILD_OUT_ABS)" "release-check build output path" "RC_PREFLIGHT_BUILD_OUT_SYMLINK"; \
	assert_no_symlink_components "$(RELEASE_CHECK_SARIF_OUT_ABS)" "release-check SARIF output path" "RC_PREFLIGHT_SARIF_OUT_SYMLINK"; \
	if [ "$(RELEASE_CHECK_BUILD_OUT_ABS)" = "$(RELEASE_CHECK_SARIF_OUT_ABS)" ]; then \
		emit_preflight_error "RC_PREFLIGHT_OUTPUT_PATH_CONFLICT" "release-check build and SARIF outputs must be different paths: build=$(RELEASE_CHECK_BUILD_OUT_ABS) sarif=$(RELEASE_CHECK_SARIF_OUT_ABS)"; \
	fi; \
	if [ -e "$(RELEASE_CHECK_BUILD_OUT_ABS)" ]; then \
		emit_preflight_error "RC_PREFLIGHT_BUILD_OUT_EXISTS" "release-check build output already exists: $(RELEASE_CHECK_BUILD_OUT_ABS)"; \
	fi; \
	if [ -e "$(RELEASE_CHECK_SARIF_OUT_ABS)" ]; then \
		emit_preflight_error "RC_PREFLIGHT_SARIF_OUT_EXISTS" "release-check SARIF output already exists: $(RELEASE_CHECK_SARIF_OUT_ABS)"; \
	fi
release-check: release-check-preflight
	@set -e; \
	cleanup_release_check_outputs() { \
		failed=0; \
		failed_count=0; \
		for output_path in "$(RELEASE_CHECK_BUILD_OUT_ABS)" "$(RELEASE_CHECK_SARIF_OUT_ABS)"; do \
			if [ -e "$$output_path" ] && ! rm -f -- "$$output_path"; then \
				echo "[RC_CLEANUP_REMOVE_FAILED] release-check cleanup failed for output path: $$output_path" >&2; \
				failed=1; \
				failed_count=$$((failed_count + 1)); \
			fi; \
		done; \
		if [ "$$failed_count" -ne 0 ]; then \
			echo "[RC_CLEANUP_REMOVE_FAILED_SUMMARY] release-check cleanup failed for $$failed_count output path(s)" >&2; \
		fi; \
		return "$$failed"; \
	}; \
	$(MAKE) check; \
	$(MAKE) test; \
	$(MAKE) test-race; \
	trap 'cleanup_release_check_outputs' EXIT; \
	$(MAKE) build BUILD_OUT=$(RELEASE_CHECK_BUILD_OUT_ABS); \
	$(MAKE) inspect-sarif INSPECT_SARIF_OUT=$(RELEASE_CHECK_SARIF_OUT_ABS); \
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

release-evidence-beta:
	./scripts/collect-release-evidence.sh --beta

inspect-sarif:
	./scripts/generate-inspect-sarif.sh "$(INSPECT_SARIF_OUT)"
