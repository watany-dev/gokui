#!/usr/bin/env bash
set -euo pipefail
set -o noclobber

umask 077

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_ROOT="${TMPDIR:-/tmp}"
WORK_DIR="$(mktemp -d "$WORK_ROOT/gokui-beta-selfcheck.XXXXXX")"

cleanup() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf -- "$WORK_DIR"
  fi
}
trap cleanup EXIT

SNAPSHOT_DIR="$WORK_DIR/repo"
mkdir -p "$SNAPSHOT_DIR"

# Snapshot current workspace content while excluding local caches and VCS state.
(
  cd "$ROOT_DIR"
  tar \
    --exclude=.git \
    --exclude=.cache \
    --exclude=./gokui \
    --exclude=./releases/evidence \
    --exclude=./releases/beta \
    -cf - .
) | (
  cd "$SNAPSHOT_DIR"
  tar -xf -
)

(
  cd "$SNAPSHOT_DIR"
  git init >/dev/null
  git config user.name "gokui-beta-selfcheck"
  git config user.email "gokui-beta-selfcheck@example.com"
  git add .
  git commit -m "beta selfcheck snapshot" >/dev/null

  export GOCACHE="$SNAPSHOT_DIR/.cache/go-build"
  export GOMODCACHE="${GOMODCACHE:-$SNAPSHOT_DIR/.cache/gomod}"
  export GOPATH="$SNAPSHOT_DIR/.cache/gopath"
  export XDG_CACHE_HOME="$SNAPSHOT_DIR/.cache/xdg"

  make beta-check
  make release-evidence-beta
)

created_evidence="$(find "$SNAPSHOT_DIR/releases/evidence" -maxdepth 1 -type f -name '*-beta-audit.md' | sort | tail -n 1)"
if [ -z "$created_evidence" ]; then
  echo "beta selfcheck failed to locate generated beta evidence file" >&2
  exit 1
fi

echo "beta selfcheck PASS"
echo "snapshot root: $SNAPSHOT_DIR"
echo "evidence file: $created_evidence"

trap - EXIT
