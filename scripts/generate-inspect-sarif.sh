#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

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

create_fresh_file_for_write() {
  local path="$1"
  local label="$2"
  local fd_var="$3"
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
  local fd
  exec {fd}>>"$tmp_path"
  if ! mv -n "$tmp_path" "$path"; then
    exec {fd}>&-
    rm -f "$tmp_path"
    echo "${label} already exists: $path" >&2
    exit 1
  fi
  printf -v "$fd_var" '%s' "$fd"
}

assert_no_symlink_components "$ROOT_DIR" "repository root path"
out_dir="$(dirname "$out_path")"
assert_no_symlink_components "$out_dir" "inspect SARIF output directory"
mkdir -p "$out_dir"
create_fresh_file_for_write "$out_path" "inspect SARIF output path" SARIF_FD

tmp_bin="$(mktemp "${TMPDIR:-/tmp}/gokui-sarif-XXXXXX")"
cleanup() {
  rm -f "$tmp_bin"
}
trap cleanup EXIT

go -C "$ROOT_DIR" build -trimpath -buildvcs=true -o "$tmp_bin" ./cmd/gokui

set +e
"$tmp_bin" inspect "$ROOT_DIR/fixtures/fake-prereq-skill" --format sarif >&"$SARIF_FD"
exit_code=$?
set -e
exec {SARIF_FD}>&-

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
