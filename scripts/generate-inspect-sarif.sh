#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
out_path_input="${1-inspect-results.sarif}"
out_path="$out_path_input"
if [[ "$out_path" != /* ]]; then
  out_path="$ROOT_DIR/$out_path"
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

create_temp_file_for_write() {
  local dir
  dir="$1"
  local base
  base="$2"
  local path_var="$3"
  local fd_var="$4"
  local tmp_path
  tmp_path="$(mktemp "$dir/.${base}.tmp.XXXXXX")"
  local fd
  exec {fd}>>"$tmp_path"
  printf -v "$path_var" '%s' "$tmp_path"
  printf -v "$fd_var" '%s' "$fd"
}

assert_under_repo_root() {
  local path="$1"
  local label="$2"
  case "$path" in
    "$ROOT_DIR"/*) ;;
    *)
      echo "${label} must resolve under repository root ($ROOT_DIR): $path" >&2
      exit 1
      ;;
  esac
}

assert_not_git_path() {
  local path="$1"
  local label="$2"
  case "$path" in
    "$ROOT_DIR/.git"|"$ROOT_DIR/.git"/*)
      echo "${label} must resolve outside .git: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_dotdot_segments() {
  local path="$1"
  local label="$2"
  case "$path" in
    */../*|*/..)
      echo "${label} must not contain '..' path segments: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_dot_segments() {
  local path="$1"
  local label="$2"
  case "$path" in
    */./*)
      echo "${label} must not contain '.' path segments: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_empty_segments() {
  local path="$1"
  local label="$2"
  case "$path" in
    *//*)
      echo "${label} must not contain empty path segments: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_surrounding_whitespace() {
  local path="$1"
  local label="$2"
  case "$path" in
    " "*|*" ")
      echo "${label} must not include leading or trailing whitespace: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_control_chars() {
  local path="$1"
  local label="$2"
  local sanitized
  sanitized="$(printf '%s' "$path" | LC_ALL=C tr -d '\000-\037\177')"
  if [ "$path" != "$sanitized" ]; then
    echo "${label} must not contain ASCII control characters" >&2
    exit 1
  fi
}

assert_non_empty_path() {
  local path="$1"
  local label="$2"
  if [ -z "$path" ]; then
    echo "${label} must be non-empty" >&2
    exit 1
  fi
}

assert_non_directory_file_path() {
  local path="$1"
  local label="$2"
  case "$path" in
    */|*/.|*/..)
      echo "${label} must be a non-directory file path: $path" >&2
      exit 1
      ;;
  esac
}

assert_sarif_output_extension() {
  local path="$1"
  local label="$2"
  case "$path" in
    *.sarif) ;;
    *)
      echo "${label} must end with .sarif: $path" >&2
      exit 1
      ;;
  esac
}

assert_no_symlink_components "$ROOT_DIR" "repository root path"
out_dir="$(dirname "$out_path")"
assert_non_empty_path "$out_path_input" "inspect SARIF output path"
assert_no_control_chars "$out_path_input" "inspect SARIF output path"
assert_no_control_chars "$out_path" "inspect SARIF output path"
assert_no_surrounding_whitespace "$out_path_input" "inspect SARIF output path"
assert_no_surrounding_whitespace "$out_path" "inspect SARIF output path"
assert_non_directory_file_path "$out_path" "inspect SARIF output path"
assert_sarif_output_extension "$out_path" "inspect SARIF output path"
assert_no_empty_segments "$out_path" "inspect SARIF output path"
assert_no_dot_segments "$out_path" "inspect SARIF output path"
assert_no_dotdot_segments "$out_path" "inspect SARIF output path"
assert_under_repo_root "$out_path" "inspect SARIF output path"
assert_not_git_path "$out_path" "inspect SARIF output path"
assert_no_symlink_components "$out_dir" "inspect SARIF output directory"
assert_no_symlink_components "$out_path" "inspect SARIF output path"
if [ -e "$out_path" ]; then
  echo "inspect SARIF output path already exists: $out_path" >&2
  exit 1
fi
mkdir -p "$out_dir"
out_base="$(basename "$out_path")"
create_temp_file_for_write "$out_dir" "$out_base" TMP_SARIF_PATH SARIF_FD

tmp_bin="$(mktemp "${TMPDIR:-/tmp}/gokui-sarif-XXXXXX")"
cleanup() {
  rm -f -- "$tmp_bin"
  if [ -n "${TMP_SARIF_PATH:-}" ]; then
    rm -f -- "$TMP_SARIF_PATH"
  fi
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

if [ ! -s "$TMP_SARIF_PATH" ]; then
  echo "inspect SARIF output file is empty: $TMP_SARIF_PATH" >&2
  exit 1
fi

grep -q '"version": "2.1.0"' "$TMP_SARIF_PATH"
grep -q '"FAKE_PREREQ_EXECUTION"' "$TMP_SARIF_PATH"

if ! mv -n "$TMP_SARIF_PATH" "$out_path"; then
  rm -f -- "$TMP_SARIF_PATH"
  echo "inspect SARIF output path already exists: $out_path" >&2
  exit 1
fi
TMP_SARIF_PATH=""

echo "generated inspect SARIF: $out_path"
