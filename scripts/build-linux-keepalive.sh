#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_HOST="${DEPLOY_HOST:-${PI_HOST:-}}"
DOCKER_PLATFORM="${OURA_DOCKER_PLATFORM:-}"
TARGET_DIR_NAME="${OURA_TARGET_DIR_NAME:-}"
DEPLOY=1

usage() {
  cat <<'USAGE'
Build the Linux keepalive binary in Docker and optionally deploy it.

Usage:
  scripts/build-linux-keepalive.sh [--platform DOCKER_PLATFORM] [--host user@host] [--no-deploy]

Examples:
  scripts/build-linux-keepalive.sh --platform linux/amd64 --no-deploy
  scripts/build-linux-keepalive.sh --platform linux/arm64 --no-deploy
  scripts/build-linux-keepalive.sh --host user@linux-host

Environment:
  DEPLOY_HOST or PI_HOST           optional remote deploy host
  OURA_DOCKER_PLATFORM             Docker platform override
  OURA_TARGET_DIR_NAME             output dir name, default target-linux-<arch>
  OURA_LINUX_BUILDER_IMAGE         Docker builder image tag
  OURA_REBUILD_BUILDER=1           rebuild the Docker builder image

When --host is set and --platform is omitted, the script asks the remote host
for uname -m and builds for that Linux architecture. Common platforms are
linux/amd64 and linux/arm64; any Docker platform supported by the rust image may
be passed explicitly.
USAGE
}

platform_from_uname() {
  case "$1" in
    arm64|aarch64) printf '%s\n' "linux/arm64" ;;
    x86_64|amd64) printf '%s\n' "linux/amd64" ;;
    armv7l|armv7*) printf '%s\n' "linux/arm/v7" ;;
    armv6l|armv6*) printf '%s\n' "linux/arm/v6" ;;
    i386|i686) printf '%s\n' "linux/386" ;;
    *) return 1 ;;
  esac
}

platform_suffix() {
  case "$1" in
    linux/arm64) printf '%s\n' "arm64" ;;
    linux/amd64) printf '%s\n' "amd64" ;;
    linux/arm/v7) printf '%s\n' "armv7" ;;
    linux/arm/v6) printf '%s\n' "armv6" ;;
    linux/386) printf '%s\n' "386" ;;
    *)
      local suffix="${1//\//-}"
      suffix="${suffix//:/-}"
      printf '%s\n' "$suffix"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      if [[ $# -lt 2 ]]; then
        echo "--host requires a value" >&2
        exit 2
      fi
      DEPLOY_HOST="$2"
      shift 2
      ;;
    --platform)
      if [[ $# -lt 2 ]]; then
        echo "--platform requires a value" >&2
        exit 2
      fi
      DOCKER_PLATFORM="$2"
      shift 2
      ;;
    --target-dir-name)
      if [[ $# -lt 2 ]]; then
        echo "--target-dir-name requires a value" >&2
        exit 2
      fi
      TARGET_DIR_NAME="$2"
      shift 2
      ;;
    --no-deploy)
      DEPLOY=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$DOCKER_PLATFORM" ]]; then
  if [[ "$DEPLOY" -eq 1 && -n "$DEPLOY_HOST" ]]; then
    if ! remote_arch="$(ssh "$DEPLOY_HOST" "uname -m" 2>/dev/null)"; then
      echo "could not detect remote architecture for $DEPLOY_HOST; pass --platform" >&2
      exit 2
    fi
    if ! DOCKER_PLATFORM="$(platform_from_uname "$remote_arch")"; then
      echo "unsupported remote arch '$remote_arch'; pass --platform explicitly" >&2
      exit 2
    fi
  else
    host_arch="$(uname -m)"
    if ! DOCKER_PLATFORM="$(platform_from_uname "$host_arch")"; then
      echo "unsupported host arch '$host_arch'; pass --platform explicitly" >&2
      exit 2
    fi
  fi
fi

platform_suffix="$(platform_suffix "$DOCKER_PLATFORM")"

if [[ -z "$TARGET_DIR_NAME" ]]; then
  TARGET_DIR_NAME="target-linux-${platform_suffix}"
fi

IMAGE="${OURA_LINUX_BUILDER_IMAGE:-oura-ring4-linux-${platform_suffix}-builder:rust-1.85}"
BINARY="$ROOT/$TARGET_DIR_NAME/release/oura-ring4-keepalive"

if [[ "${OURA_REBUILD_BUILDER:-0}" == "1" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build --platform "$DOCKER_PLATFORM" -t "$IMAGE" - <<'DOCKERFILE'
FROM rust:1.85-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      file \
      libdbus-1-dev \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE
fi

docker run --rm --platform "$DOCKER_PLATFORM" \
  -v "$ROOT:/work" \
  -v oura-cargo-registry:/usr/local/cargo/registry \
  -v oura-cargo-git:/usr/local/cargo/git \
  -w /work \
  -e CARGO_TARGET_DIR="/work/$TARGET_DIR_NAME" \
  "$IMAGE" \
  sh -c 'set -eu
    export PATH=/usr/local/cargo/bin:$PATH
    cargo build --release --bin oura-ring4-keepalive
    file "$CARGO_TARGET_DIR/release/oura-ring4-keepalive"
  '

if [[ "$DEPLOY" -eq 1 ]]; then
  if [[ -z "$DEPLOY_HOST" ]]; then
    echo "--host is required unless --no-deploy is set" >&2
    exit 2
  fi
  ssh "$DEPLOY_HOST" "mkdir -p ~/oura-ring4-ble/$TARGET_DIR_NAME/release"
  rsync -az "$BINARY" "$DEPLOY_HOST:~/oura-ring4-ble/$TARGET_DIR_NAME/release/"
  ssh "$DEPLOY_HOST" "set -eu
    cd ~/oura-ring4-ble
    file $TARGET_DIR_NAME/release/oura-ring4-keepalive
    ldd $TARGET_DIR_NAME/release/oura-ring4-keepalive
    ./$TARGET_DIR_NAME/release/oura-ring4-keepalive --help >/dev/null
  "
fi
