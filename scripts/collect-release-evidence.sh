#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/releases/evidence"
LOG_DIR="$OUT_DIR/logs"
WITH_VULN=0
AUDIT_KIND="offline-audit"
EVIDENCE_MODE="offline"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--with-vuln]

Options:
  --with-vuln   Also run 'make vuln' and record the result.
USAGE
}

assert_no_symlink_components() {
  local path="$1"
  local label="$2"
  local current="$path"
  while :; do
    if [ -L "$current" ]; then
      echo "${label} contains symlink path component: $current" >&2
      exit 1
    fi
    local parent
    parent="$(dirname "$current")"
    if [ "$parent" = "$current" ]; then
      break
    fi
    current="$parent"
  done
}

create_fresh_file() {
  local path="$1"
  local label="$2"
  assert_no_symlink_components "$path" "$label"
  if [ -e "$path" ]; then
    echo "${label} already exists: $path" >&2
    exit 1
  fi

  local dir
  dir="$(dirname "$path")"
  local base
  base="$(basename "$path")"
  local tmp_path
  tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"
  if ! mv -n "$tmp_path" "$path"; then
    rm -f "$tmp_path"
    echo "${label} already exists: $path" >&2
    exit 1
  fi
}

assert_no_symlink_components "$ROOT_DIR" "repository root path"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-vuln)
      WITH_VULN=1
      AUDIT_KIND="online-audit"
      EVIDENCE_MODE="online"
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

assert_no_symlink_components "$OUT_DIR" "evidence directory"
assert_no_symlink_components "$LOG_DIR" "evidence log directory"
mkdir -p "$OUT_DIR" "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
BASENAME="${TS}-${COMMIT_SHA}-${AUDIT_KIND}"
OUT_PATH="$OUT_DIR/${BASENAME}.md"
create_fresh_file "$OUT_PATH" "evidence path"
exec {EVIDENCE_FD}>>"$OUT_PATH"

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
  } >&${EVIDENCE_FD}
}

run_step() {
  local step_name="$1"
  local command_text="$2"
  local log_path="$3"

  create_fresh_file "$log_path" "log path"
  local log_fd
  exec {log_fd}>>"$log_path"

  set +e
  bash -lc "cd \"$ROOT_DIR\" && ${command_text}" >&"$log_fd" 2>&1
  local rc=$?
  set -e
  exec {log_fd}>&-

  append_step_result "$step_name" "$command_text" "$rc" "$log_path"
}

run_git_clean_check() {
  local step_name="git status clean"
  local command_text="git status --short --untracked-files=no"
  local log_path="$LOG_DIR/${BASENAME}-git-status.log"

  create_fresh_file "$log_path" "log path"
  local log_fd
  exec {log_fd}>>"$log_path"

  set +e
  bash -lc "cd \"$ROOT_DIR\" && git status --short --untracked-files=no" >&"$log_fd" 2>&1
  local rc=$?
  set -e

  if [ "$rc" -eq 0 ] && [ -s "$log_path" ]; then
    rc=1
    {
      echo
      echo "expected clean tracked working tree, but git status returned output"
    } >&"$log_fd"
  fi
  exec {log_fd}>&-

  append_step_result "$step_name" "$command_text" "$rc" "$log_path"
}

{
  echo "# Release Evidence - ${TS}"
  echo
  echo "## Metadata"
  echo "- Generated (UTC): ${TS}"
  echo "- Mode: ${EVIDENCE_MODE}"
  echo "- Candidate commit SHA: ${COMMIT_SHA}"
  echo "- Host: $(uname -srm)"
  echo "- Go version: $(go version 2>/dev/null || echo unknown)"
  echo
  echo "## Automated Steps"
} >&${EVIDENCE_FD}

run_git_clean_check
run_step "release-check-offline" "GOCACHE=\"$ROOT_DIR/.cache/go-build\" GOMODCACHE=\"$ROOT_DIR/.cache/gomod\" GOPATH=\"$ROOT_DIR/.cache/gopath\" XDG_CACHE_HOME=\"$ROOT_DIR/.cache/xdg\" BUILD_OUT=\"$ROOT_DIR/.cache/gokui-release-evidence\" make release-check-offline" "$LOG_DIR/${BASENAME}-release-check-offline.log"

if [ "$WITH_VULN" -eq 1 ] && [ "$FAILED_STEPS" -eq 0 ]; then
  run_step "vuln" "GOCACHE=\"$ROOT_DIR/.cache/go-build\" GOMODCACHE=\"$ROOT_DIR/.cache/gomod\" GOPATH=\"$ROOT_DIR/.cache/gopath\" XDG_CACHE_HOME=\"$ROOT_DIR/.cache/xdg\" make vuln" "$LOG_DIR/${BASENAME}-vuln.log"
elif [ "$WITH_VULN" -eq 1 ]; then
  {
    echo "- vuln: SKIPPED"
    echo "  - reason: skipped because prior step already failed"
  } >&${EVIDENCE_FD}
else
  {
    echo "- vuln: SKIPPED"
    echo "  - reason: run with --with-vuln to include online vulnerability check"
  } >&${EVIDENCE_FD}
fi

if [ "$FAILED_STEPS" -eq 0 ]; then
  run_step "cleanup evidence build artifact" "rm -f \"$ROOT_DIR/.cache/gokui-release-evidence\"" "$LOG_DIR/${BASENAME}-cleanup.log"
else
  {
    echo "- cleanup evidence build artifact: SKIPPED"
    echo "  - reason: preserve failing build artifact for investigation"
  } >&${EVIDENCE_FD}
fi

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
} >&${EVIDENCE_FD}

exec {EVIDENCE_FD}>&-

echo "Created $OUT_PATH"
if [ "$FAILED_STEPS" -ne 0 ]; then
  exit 1
fi
