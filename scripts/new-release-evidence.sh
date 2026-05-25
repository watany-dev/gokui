#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_PATH="$ROOT_DIR/RELEASE_EVIDENCE_TEMPLATE.md"
OUT_DIR="$ROOT_DIR/releases/evidence"

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
  local fd_var="$4"
  local tmp_path
  tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"
  local fd
  exec {fd}>>"$tmp_path"
  printf -v "$path_var" '%s' "$tmp_path"
  printf -v "$fd_var" '%s' "$fd"
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

assert_no_symlink_components "$ROOT_DIR" "repository root path"

if [ ! -f "$TEMPLATE_PATH" ]; then
  echo "missing template: $TEMPLATE_PATH" >&2
  exit 1
fi

assert_no_symlink_components "$TEMPLATE_PATH" "release evidence template path"
assert_no_symlink_components "$OUT_DIR" "release evidence output directory"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
OUT_PATH="$OUT_DIR/${TS}-${COMMIT_SHA}.md"
assert_output_path_available "$OUT_PATH" "release evidence output path"
OUT_BASENAME="$(basename "$OUT_PATH")"
create_temp_file_for_write "$OUT_DIR" "$OUT_BASENAME" TMP_EVIDENCE_PATH EVIDENCE_FD
cleanup() {
  if [ -n "${TMP_EVIDENCE_PATH:-}" ]; then
    rm -f "$TMP_EVIDENCE_PATH"
  fi
}
trap cleanup EXIT

{
  echo "# Release Evidence - $TS"
  echo
  echo "- Generated (UTC): $TS"
  echo "- Candidate commit SHA: $COMMIT_SHA"
  echo
  cat "$TEMPLATE_PATH"
} >&${EVIDENCE_FD}
exec {EVIDENCE_FD}>&-
if ! mv -n "$TMP_EVIDENCE_PATH" "$OUT_PATH"; then
  rm -f "$TMP_EVIDENCE_PATH"
  echo "release evidence output path already exists: $OUT_PATH" >&2
  exit 1
fi
TMP_EVIDENCE_PATH=""

echo "Created $OUT_PATH"
