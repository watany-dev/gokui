#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-}"
VERSION="${2:-}"
COMMIT="${3:-}"
DATE="${4:-}"

if [ -z "$OUT_DIR" ] || [ -z "$VERSION" ] || [ -z "$COMMIT" ] || [ -z "$DATE" ]; then
  echo "usage: $(basename "$0") <out-dir> <version> <commit> <date-iso8601>" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

build_one() {
  local goos="$1"
  local goarch="$2"
  local ext=""
  if [ "$goos" = "windows" ]; then
    ext=".exe"
  fi

  local output="$OUT_DIR/gokui-${goos}-${goarch}${ext}"

  GOOS="$goos" GOARCH="$goarch" \
    go build \
      -trimpath \
      -buildvcs=true \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o "$output" \
      ./cmd/gokui
}

build_one darwin amd64
build_one darwin arm64
build_one linux amd64
build_one linux arm64
build_one windows amd64

(
  cd "$OUT_DIR"
  sha256sum gokui-* > SHA256SUMS
)
