#!/bin/sh
set -eu

REPO="dsecurity49/safe-migrate"
BIN_NAME="safe-migrate"

VERSION="latest"
TARGET_OVERRIDE=""
PREFIX_OVERRIDE=""
INSTALL_DIR_OVERRIDE=""
FORCE=0
DRY_RUN=0
VERBOSE=0

log()  { printf '%s\n' "$*" >&2; }
warn() { printf 'Warning: %s\n' "$*" >&2; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    log "[dry-run] $*"
  else
    "$@"
  fi
}

normalize_version() {
  case "$1" in
    latest) printf '%s\n' latest ;;
    v*)     printf '%s\n' "$1" ;;
    *)      printf 'v%s\n' "$1" ;;
  esac
}

detect_linux_flavor() {
  case "${TERMUX_VERSION:-}:${ANDROID_ROOT:-}" in
    :) ;;
    *:*) printf '%s\n' musl; return ;;
  esac

  case "${PREFIX:-}" in
    /data/data/com.termux/*) printf '%s\n' musl; return ;;
  esac

  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    printf '%s\n' musl
    return
  fi

  printf '%s\n' gnu
}

build_url() {
  version="$1"
  target="$2"

  if [ "$version" = latest ]; then
    printf 'https://github.com/%s/releases/latest/download/%s-%s.tar.gz' \
      "$REPO" "$BIN_NAME" "$target"
  else
    printf 'https://github.com/%s/releases/download/%s/%s-%s.tar.gz' \
      "$REPO" "$version" "$BIN_NAME" "$target"
  fi
}

target_candidates() {
  os="$1"
  arch="$2"

  case "$TARGET_OVERRIDE" in
    "")
      ;;
    *)
      printf '%s\n' "$TARGET_OVERRIDE"
      return
      ;;
  esac

  case "$os" in
    Darwin)
      case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "Unsupported architecture: $arch" ;;
      esac
      printf '%s\n' "${arch}-apple-darwin"
      ;;
    Linux)
      case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "Unsupported architecture: $arch" ;;
      esac

      if [ "$(detect_linux_flavor)" = musl ]; then
        printf '%s\n' "${arch}-unknown-linux-musl ${arch}-unknown-linux-gnu"
      else
        printf '%s\n' "${arch}-unknown-linux-gnu ${arch}-unknown-linux-musl"
      fi
      ;;
    *)
      die "Unsupported OS: $os"
      ;;
  esac
}

download_asset() {
  version="$1"
  target="$2"
  url="$(build_url "$version" "$target")"
  out="${TMP_DIR}/${BIN_NAME}-${target}.tar.gz"
  part="${out}.partial"

  [ "$VERBOSE" -eq 1 ] && log "Trying ${target}: ${url}"

  rm -f "$part"

  if ! curl -#fL -C - -o "$part" "$url"; then
    rm -f "$part"
    return 1
  fi

  if ! tar -tzf "$part" >/dev/null 2>&1; then
    rm -f "$part"
    return 1
  fi

  mv "$part" "$out"
  printf '%s\n' "$out"
}

pick_install_dir() {
  if [ -n "$INSTALL_DIR_OVERRIDE" ]; then
    printf '%s\n' "$INSTALL_DIR_OVERRIDE"
    return
  fi

  if [ -n "$PREFIX_OVERRIDE" ]; then
    printf '%s\n' "${PREFIX_OVERRIDE%/}/bin"
    return
  fi

  case "${TERMUX_VERSION:-}:${ANDROID_ROOT:-}" in
    :) ;;
    *:*)
      if [ -n "${PREFIX:-}" ]; then
        printf '%s/bin\n' "$PREFIX"
        return
      fi
      ;;
  esac

  if [ -w "/usr/local/bin" ]; then
    printf '%s\n' "/usr/local/bin"
    return
  fi

  printf '%s\n' "${HOME}/.local/bin"
}

usage() {
  cat <<EOF
Usage: ${0##*/} [options]

Options:
  --version <tag>      Install a specific version (default: latest)
  --target <triplet>   Force a release target, e.g. aarch64-unknown-linux-musl
  --prefix <dir>       Install under this prefix, e.g. /usr/local or \$HOME/.local
  --install-dir <dir>  Install into this exact directory
  --force              Overwrite an existing binary
  --dry-run            Show actions without changing anything
  -v, --verbose        Show download attempts
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --target)
      [ $# -ge 2 ] || die "--target requires a value"
      TARGET_OVERRIDE="$2"
      shift 2
      ;;
    --prefix)
      [ $# -ge 2 ] || die "--prefix requires a value"
      PREFIX_OVERRIDE="$2"
      shift 2
      ;;
    --install-dir)
      [ $# -ge 2 ] || die "--install-dir requires a value"
      INSTALL_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -v|--verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

need curl
need tar
need uname
need sed
need head
need grep
need mktemp
need find
need cp
need chmod
need mkdir
need mv

VERSION="$(normalize_version "$VERSION")"

log "Detecting operating system and architecture..."

OS="$(uname -s)"
ARCH="$(uname -m)"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

CANDIDATES="$(target_candidates "$OS" "$ARCH")"

TAR_FILE=""
SELECTED_TARGET=""

for candidate in $CANDIDATES; do
  if TAR_FILE="$(download_asset "$VERSION" "$candidate")"; then
    SELECTED_TARGET="$candidate"
    break
  fi
done

[ -n "$TAR_FILE" ] || {
  printf 'Error: no matching release asset found for %s\n' "$VERSION" >&2
  printf 'Tried targets:\n' >&2
  for t in $CANDIDATES; do
    printf '  - %s\n' "$t" >&2
  done
  exit 1
}

log "Selected target: ${SELECTED_TARGET}"
log "Extracting archive..."
run tar -xzf "$TAR_FILE" -C "$TMP_DIR"

BIN_PATH="$(find "$TMP_DIR" -type f -name "$BIN_NAME" | head -n 1 || true)"
[ -n "$BIN_PATH" ] || die "Binary not found inside archive"

INSTALL_DIR="$(pick_install_dir)"
DEST="${INSTALL_DIR}/${BIN_NAME}"

if [ -e "$DEST" ] && [ "$FORCE" -ne 1 ]; then
  die "${DEST} already exists. Use --force to overwrite."
fi

run mkdir -p "$INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "No write permission for ${INSTALL_DIR}. Use --install-dir <dir> or --prefix <dir>."

log "Installing to ${INSTALL_DIR}..."
run cp "$BIN_PATH" "$DEST"
run chmod +x "$DEST"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "${INSTALL_DIR} is not in your PATH" ;;
esac

log "----------------------------------------"
log "${BIN_NAME} ${VERSION} installed successfully!"
log "Run '${BIN_NAME} --help' to get started."
log "----------------------------------------"
