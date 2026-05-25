#!/usr/bin/env bash
set -euo pipefail

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
assert_no_symlink_components "$OUT_PATH" "release evidence output path"
if [ -e "$OUT_PATH" ]; then
  echo "release evidence output already exists: $OUT_PATH" >&2
  exit 1
fi

{
  echo "# Release Evidence - $TS"
  echo
  echo "- Generated (UTC): $TS"
  echo "- Candidate commit SHA: $COMMIT_SHA"
  echo
  cat "$TEMPLATE_PATH"
} > "$OUT_PATH"

echo "Created $OUT_PATH"
