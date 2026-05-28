#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/releases/evidence"
LOG_DIR="$OUT_DIR/logs"
EVIDENCE_GOCACHE="${GOCACHE:-$ROOT_DIR/.cache/go-build}"
EVIDENCE_GOMODCACHE="${GOMODCACHE:-$ROOT_DIR/.cache/gomod}"
EVIDENCE_GOPATH="${GOPATH:-$ROOT_DIR/.cache/gopath}"
EVIDENCE_XDG_CACHE_HOME="${XDG_CACHE_HOME:-$ROOT_DIR/.cache/xdg}"
EVIDENCE_FD=9
LOG_FD=8
WITH_VULN=0
AUDIT_KIND="offline-audit"
EVIDENCE_MODE="offline"
GATE_STEP_NAME="release-check-offline"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--with-vuln] [--beta]

Options:
  --with-vuln   Also run 'make vuln' and record the result.
  --beta        Run beta gate ('make beta-check') instead of release-check-offline.
                Cannot be combined with --with-vuln.
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

create_temp_file_for_write() {
  local dir="$1"
  local base="$2"
  local path_var="$3"
  local tmp_path
  tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"
  printf -v "$path_var" '%s' "$tmp_path"
}

assert_output_path_available() {
  local path="$1"
  local label="$2"
  assert_no_symlink_components "$path" "$label"
  if [ -e "$path" ]; then
    echo "${label} already exists: $path" >&2
    exit 1
  fi
}

resolve_commit_sha() {
  local commit_sha
  if ! commit_sha="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null)"; then
    echo "failed to resolve candidate commit SHA from git HEAD" >&2
    exit 1
  fi
  case "$commit_sha" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *)
      echo "git HEAD commit SHA must be lowercase 40-hex: $commit_sha" >&2
      exit 1
      ;;
  esac
  printf '%s\n' "$commit_sha"
}

assert_no_symlink_components "$ROOT_DIR" "repository root path"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-vuln)
      WITH_VULN=1
      AUDIT_KIND="online-audit"
      EVIDENCE_MODE="online"
      ;;
    --beta)
      AUDIT_KIND="beta-audit"
      EVIDENCE_MODE="beta"
      GATE_STEP_NAME="beta-check"
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

if [ "$WITH_VULN" -eq 1 ] && [ "$GATE_STEP_NAME" = "beta-check" ]; then
  echo "--with-vuln cannot be combined with --beta" >&2
  exit 1
fi

assert_no_symlink_components "$OUT_DIR" "evidence directory"
assert_no_symlink_components "$LOG_DIR" "evidence log directory"
mkdir -p "$OUT_DIR" "$LOG_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT_SHA="$(resolve_commit_sha)"
BASENAME="${TS}-${COMMIT_SHA}-${AUDIT_KIND}"
OUT_PATH="$OUT_DIR/${BASENAME}.md"
assert_output_path_available "$OUT_PATH" "evidence path"
OUT_BASENAME="$(basename "$OUT_PATH")"
create_temp_file_for_write "$OUT_DIR" "$OUT_BASENAME" TMP_EVIDENCE_PATH
eval "exec ${EVIDENCE_FD}>>\"$TMP_EVIDENCE_PATH\""
cleanup() {
  if [ -n "${TMP_EVIDENCE_PATH:-}" ]; then
    rm -f -- "$TMP_EVIDENCE_PATH"
  fi
}
trap cleanup EXIT

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

  assert_output_path_available "$log_path" "log path"
  local log_basename
  log_basename="$(basename "$log_path")"
  local tmp_log_path
  create_temp_file_for_write "$LOG_DIR" "$log_basename" tmp_log_path
  eval "exec ${LOG_FD}>>\"$tmp_log_path\""

  set +e
  bash -lc "cd \"$ROOT_DIR\" && ${command_text}" >&"${LOG_FD}" 2>&1
  local rc=$?
  set -e
  eval "exec ${LOG_FD}>&-"
  if ! mv -n "$tmp_log_path" "$log_path"; then
    rm -f -- "$tmp_log_path"
    echo "log path already exists: $log_path" >&2
    exit 1
  fi

  append_step_result "$step_name" "$command_text" "$rc" "$log_path"
}

run_git_clean_check() {
  local step_name="git status clean"
  local command_text="git status --short"
  local log_path="$LOG_DIR/${BASENAME}-git-status.log"

  assert_output_path_available "$log_path" "log path"
  local log_basename
  log_basename="$(basename "$log_path")"
  local tmp_log_path
  create_temp_file_for_write "$LOG_DIR" "$log_basename" tmp_log_path
  eval "exec ${LOG_FD}>>\"$tmp_log_path\""

  set +e
  bash -lc "cd \"$ROOT_DIR\" && git status --short" >&"${LOG_FD}" 2>&1
  local rc=$?
  set -e

  if [ "$rc" -eq 0 ] && [ -s "$tmp_log_path" ]; then
    rc=1
    {
      echo
      echo "expected clean tracked working tree, but git status returned output"
    } >&"${LOG_FD}"
  fi
  eval "exec ${LOG_FD}>&-"
  if ! mv -n "$tmp_log_path" "$log_path"; then
    rm -f -- "$tmp_log_path"
    echo "log path already exists: $log_path" >&2
    exit 1
  fi

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
  echo "- GOCACHE: ${EVIDENCE_GOCACHE}"
  echo "- GOMODCACHE: ${EVIDENCE_GOMODCACHE}"
  echo "- GOPATH: ${EVIDENCE_GOPATH}"
  echo "- XDG_CACHE_HOME: ${EVIDENCE_XDG_CACHE_HOME}"
  echo
  echo "## Automated Steps"
} >&${EVIDENCE_FD}

run_git_clean_check
if [ "$FAILED_STEPS" -eq 0 ] && [ "$GATE_STEP_NAME" = "beta-check" ]; then
  run_step "$GATE_STEP_NAME" "GOCACHE=\"$EVIDENCE_GOCACHE\" GOMODCACHE=\"$EVIDENCE_GOMODCACHE\" GOPATH=\"$EVIDENCE_GOPATH\" XDG_CACHE_HOME=\"$EVIDENCE_XDG_CACHE_HOME\" BETA_CHECK_BUILD_OUT=\"$ROOT_DIR/.cache/gokui-beta-evidence\" BETA_CHECK_SARIF_OUT=\"$ROOT_DIR/.cache/inspect-results-beta-evidence.sarif\" make beta-check" "$LOG_DIR/${BASENAME}-${GATE_STEP_NAME}.log"
elif [ "$FAILED_STEPS" -eq 0 ]; then
  run_step "$GATE_STEP_NAME" "GOCACHE=\"$EVIDENCE_GOCACHE\" GOMODCACHE=\"$EVIDENCE_GOMODCACHE\" GOPATH=\"$EVIDENCE_GOPATH\" XDG_CACHE_HOME=\"$EVIDENCE_XDG_CACHE_HOME\" BUILD_OUT=\"$ROOT_DIR/.cache/gokui-release-evidence\" make release-check-offline" "$LOG_DIR/${BASENAME}-${GATE_STEP_NAME}.log"
else
  {
    echo "- ${GATE_STEP_NAME}: SKIPPED"
    echo "  - reason: skipped because git status clean check failed"
  } >&${EVIDENCE_FD}
fi

if [ "$WITH_VULN" -eq 1 ] && [ "$FAILED_STEPS" -eq 0 ]; then
  run_step "vuln" "GOCACHE=\"$EVIDENCE_GOCACHE\" GOMODCACHE=\"$EVIDENCE_GOMODCACHE\" GOPATH=\"$EVIDENCE_GOPATH\" XDG_CACHE_HOME=\"$EVIDENCE_XDG_CACHE_HOME\" make vuln" "$LOG_DIR/${BASENAME}-vuln.log"
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
  if [ "$GATE_STEP_NAME" = "beta-check" ]; then
    run_step "cleanup evidence build artifact" "rm -f -- \"$ROOT_DIR/.cache/gokui-beta-evidence\" \"$ROOT_DIR/.cache/inspect-results-beta-evidence.sarif\"" "$LOG_DIR/${BASENAME}-cleanup.log"
  else
    run_step "cleanup evidence build artifact" "rm -f -- \"$ROOT_DIR/.cache/gokui-release-evidence\"" "$LOG_DIR/${BASENAME}-cleanup.log"
  fi
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

eval "exec ${EVIDENCE_FD}>&-"
if ! mv -n "$TMP_EVIDENCE_PATH" "$OUT_PATH"; then
  rm -f -- "$TMP_EVIDENCE_PATH"
  echo "evidence path already exists: $OUT_PATH" >&2
  exit 1
fi
TMP_EVIDENCE_PATH=""

echo "Created $OUT_PATH"
if [ "$FAILED_STEPS" -ne 0 ]; then
  exit 1
fi
