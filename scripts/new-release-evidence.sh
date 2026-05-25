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
create_fresh_file "$OUT_PATH" "release evidence output path"
exec {EVIDENCE_FD}>>"$OUT_PATH"

{
  echo "# Release Evidence - $TS"
  echo
  echo "- Generated (UTC): $TS"
  echo "- Candidate commit SHA: $COMMIT_SHA"
  echo
  cat "$TEMPLATE_PATH"
} >&${EVIDENCE_FD}
exec {EVIDENCE_FD}>&-

echo "Created $OUT_PATH"
