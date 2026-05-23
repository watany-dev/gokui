#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/releases/evidence"
LOG_DIR="$OUT_DIR/logs"
WITH_VULN=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--with-vuln]

Options:
  --with-vuln   Also run 'make vuln' and record the result.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-vuln)
      WITH_VULN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

mkdir -p "$OUT_DIR" "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
BASENAME="${TS}-${COMMIT_SHA}-offline-audit"
OUT_PATH="$OUT_DIR/${BASENAME}.md"

FAILED_STEPS=0

append_step_result() {
  local step_name="$1"
  local command_text="$2"
  local rc="$3"
  local log_path="$4"

  local result="PASS"
  if [ "$rc" -ne 0 ]; then
    result="FAIL (exit=${rc})"
    FAILED_STEPS=$((FAILED_STEPS + 1))
  fi

  {
    echo "- ${step_name}: ${result}"
    echo "  - command: \`${command_text}\`"
    echo "  - log: \`${log_path#"$ROOT_DIR"/}\`"
  } >> "$OUT_PATH"
}

run_step() {
  local step_name="$1"
  local command_text="$2"
  local log_path="$3"

  set +e
  bash -lc "cd \"$ROOT_DIR\" && ${command_text}" >"$log_path" 2>&1
  local rc=$?
  set -e

  append_step_result "$step_name" "$command_text" "$rc" "$log_path"
}

run_git_clean_check() {
  local step_name="git status clean"
  local command_text="git status --short"
  local log_path="$LOG_DIR/${BASENAME}-git-status.log"

  set +e
  bash -lc "cd \"$ROOT_DIR\" && git status --short" >"$log_path" 2>&1
  local rc=$?
  set -e

  if [ "$rc" -eq 0 ] && [ -s "$log_path" ]; then
    rc=1
    echo >> "$log_path"
    echo "expected clean working tree, but git status returned output" >> "$log_path"
  fi

  append_step_result "$step_name" "$command_text" "$rc" "$log_path"
}

{
  echo "# Release Evidence - ${TS}"
  echo
  echo "## Metadata"
  echo "- Generated (UTC): ${TS}"
  echo "- Candidate commit SHA: ${COMMIT_SHA}"
  echo "- Host: $(uname -srm)"
  echo "- Go version: $(go version 2>/dev/null || echo unknown)"
  echo
  echo "## Automated Steps"
} > "$OUT_PATH"

run_git_clean_check
run_step "release-check-offline" "GOCACHE=$ROOT_DIR/.cache/go-build GOMODCACHE=$ROOT_DIR/.cache/gomod GOPATH=$ROOT_DIR/.cache/gopath XDG_CACHE_HOME=$ROOT_DIR/.cache/xdg make release-check-offline" "$LOG_DIR/${BASENAME}-release-check-offline.log"

if [ "$WITH_VULN" -eq 1 ]; then
  run_step "vuln" "GOCACHE=$ROOT_DIR/.cache/go-build GOMODCACHE=$ROOT_DIR/.cache/gomod GOPATH=$ROOT_DIR/.cache/gopath XDG_CACHE_HOME=$ROOT_DIR/.cache/xdg make vuln" "$LOG_DIR/${BASENAME}-vuln.log"
else
  {
    echo "- vuln: SKIPPED"
    echo "  - reason: run with --with-vuln to include online vulnerability check"
  } >> "$OUT_PATH"
fi

run_step "cleanup binary" "rm -f gokui" "$LOG_DIR/${BASENAME}-cleanup.log"

{
  echo
  echo "## Summary"
  if [ "$FAILED_STEPS" -eq 0 ]; then
    echo "- Overall result: PASS"
  else
    echo "- Overall result: FAIL (${FAILED_STEPS} step(s))"
  fi
  echo "- Evidence file: \`${OUT_PATH#"$ROOT_DIR"/}\`"
  echo "- Logs directory: \`${LOG_DIR#"$ROOT_DIR"/}\`"
} >> "$OUT_PATH"

echo "Created $OUT_PATH"
if [ "$FAILED_STEPS" -ne 0 ]; then
  exit 1
fi
