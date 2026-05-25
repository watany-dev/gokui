#!/usr/bin/env bash
set -euo pipefail

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
out_path="${1:-inspect-results.sarif}"
if [[ "$out_path" != /* ]]; then
  out_path="$(pwd)/$out_path"
fi

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

assert_no_symlink_components "$ROOT_DIR" "repository root path"
assert_no_symlink_components "$out_path" "inspect SARIF output path"
mkdir -p "$(dirname "$out_path")"
if [ -e "$out_path" ]; then
  echo "inspect SARIF output already exists: $out_path" >&2
  exit 1
fi

tmp_bin="$(mktemp "${TMPDIR:-/tmp}/gokui-sarif-XXXXXX")"
cleanup() {
  rm -f "$tmp_bin"
}
trap cleanup EXIT

go -C "$ROOT_DIR" build -trimpath -buildvcs=true -o "$tmp_bin" ./cmd/gokui

set +e
"$tmp_bin" inspect "$ROOT_DIR/fixtures/fake-prereq-skill" --format sarif > "$out_path"
exit_code=$?
set -e

if [ "$exit_code" -ne 2 ]; then
  echo "expected inspect exit code 2 for rejected fixture, got $exit_code" >&2
  exit 1
fi

if [ ! -s "$out_path" ]; then
  echo "inspect SARIF output file is empty: $out_path" >&2
  exit 1
fi

grep -q '"version": "2.1.0"' "$out_path"
grep -q '"FAKE_PREREQ_EXECUTION"' "$out_path"

echo "generated inspect SARIF: $out_path"
