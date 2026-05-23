#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE_PATH="$ROOT_DIR/RELEASE_EVIDENCE_TEMPLATE.md"
OUT_DIR="$ROOT_DIR/releases/evidence"

if [ ! -f "$TEMPLATE_PATH" ]; then
  echo "missing template: $TEMPLATE_PATH" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
COMMIT_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
OUT_PATH="$OUT_DIR/${TS}-${COMMIT_SHA}.md"

{
  echo "# Release Evidence - $TS"
  echo
  echo "- Generated (UTC): $TS"
  echo "- Candidate commit SHA: $COMMIT_SHA"
  echo
  cat "$TEMPLATE_PATH"
} > "$OUT_PATH"

echo "Created $OUT_PATH"
