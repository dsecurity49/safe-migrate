#!/bin/sh
set -eu

REPO="dsecurity49/safe-migrate"
BIN_NAME="safe-migrate"

REQUESTED_VERSION="latest"
TARGET_OVERRIDE=""
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

fetch_latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1
}

detect_linux_flavor() {
  # Check for Termux (Android) — always musl
  if [ -n "${TERMUX_VERSION:-}" ] || [ -n "${ANDROID_ROOT:-}" ]; then
    printf '%s\n' musl
    return
  fi

  # Check for Termux prefix path
  case "${PREFIX:-}" in
    /data/data/com.termux/*) printf '%s\n' musl; return ;;
  esac

  # Check if musl is detected via ldd
  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    printf '%s\n' musl
    return
  fi

  # Default to glibc (GNU)
  printf '%s\n' gnu
}

build_url() {
  version="$1"
  target="$2"
  printf 'https://github.com/%s/releases/download/%s/%s-%s.tar.gz' \
    "$REPO" "$version" "$BIN_NAME" "$target"
}

candidate_targets() {
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
        printf '%s\n' "${arch}-unknown-linux-musl"
        printf '%s\n' "${arch}-unknown-linux-gnu"
      else
        printf '%s\n' "${arch}-unknown-linux-gnu"
        printf '%s\n' "${arch}-unknown-linux-musl"
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

  if [ "$VERBOSE" -eq 1 ]; then
    curl -fL --progress-bar -o "$part" "$url" || {
      rm -f "$part"
      return 1
    }
  else
    curl -fsSL -o "$part" "$url" || {
      rm -f "$part"
      return 1
    }
  fi

  # Verify checksum if available
  sha_url="${url}.sha256"
  sha_file="${part}.sha256"
  if curl -fsSL -o "$sha_file" "$sha_url" 2>/dev/null; then
    expected=$(cut -d' ' -f1 < "$sha_file" 2>/dev/null || true)
    if [ -n "$expected" ]; then
      actual=$(sha256sum "$part" 2>/dev/null | cut -d' ' -f1 || true)
      if [ "$actual" != "$expected" ]; then
        rm -f "$part" "$sha_file"
        log "Checksum mismatch for ${target}. Expected ${expected}, got ${actual}."
        return 1
      fi
      [ "$VERBOSE" -eq 1 ] && log "Checksum verified for ${target}"
    fi
    rm -f "$sha_file"
  fi

  tar -tzf "$part" >/dev/null 2>&1 || {
    rm -f "$part"
    return 1
  }

  mv "$part" "$out"
  printf '%s\n' "$out"
}

pick_install_dir() {
  if [ -n "$INSTALL_DIR_OVERRIDE" ]; then
    printf '%s\n' "$INSTALL_DIR_OVERRIDE"
    return
  fi

  if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && [ -w "${PREFIX}/bin" ]; then
    printf '%s\n' "${PREFIX}/bin"
    return
  fi

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
  --target <triplet>    Force a release target, e.g. aarch64-unknown-linux-musl
  --install-dir <dir>   Install into this exact directory
  --bin-dir <dir>       Alias for --install-dir
  --force               Overwrite an existing binary
  --dry-run             Show actions without changing anything
  -v, --verbose         Show download attempts
  -h, --help            Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      REQUESTED_VERSION="$2"
      shift 2
      ;;
    --version=*)
      REQUESTED_VERSION="${1#--version=}"
      shift
      ;;
    --target)
      [ $# -ge 2 ] || die "--target requires a value"
      TARGET_OVERRIDE="$2"
      shift 2
      ;;
    --target=*)
      TARGET_OVERRIDE="${1#--target=}"
      shift
      ;;
    --install-dir|--bin-dir)
      [ $# -ge 2 ] || die "$1 requires a value"
      INSTALL_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --install-dir=*|--bin-dir=*)
      INSTALL_DIR_OVERRIDE="${1#*=}"
      shift
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
need cp
need chmod
need mkdir
need mv
need rm

REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"

log "Detecting operating system and architecture..."

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$REQUESTED_VERSION" = "latest" ]; then
  log "Fetching latest release version..."
  RESOLVED_VERSION="$(fetch_latest_version)"
  [ -n "$RESOLVED_VERSION" ] || die "Failed to fetch latest release version"
else
  RESOLVED_VERSION="$REQUESTED_VERSION"
fi

log "Using version: ${RESOLVED_VERSION}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM

CANDIDATES="$(candidate_targets "$OS" "$ARCH")"

TAR_FILE=""
SELECTED_TARGET=""

for candidate in $CANDIDATES; do
  if TAR_FILE="$(download_asset "$RESOLVED_VERSION" "$candidate")"; then
    SELECTED_TARGET="$candidate"
    break
  fi
done

if [ -z "$TAR_FILE" ]; then
  printf 'Error: no matching release asset found for %s\n' "$RESOLVED_VERSION" >&2
  printf 'Tried targets:\n' >&2
  for t in $CANDIDATES; do
    printf '  - %s\n' "$t" >&2
  done
  exit 1
fi

log "Selected target: ${SELECTED_TARGET}"
log "Extracting archive..."
run tar -xzf "$TAR_FILE" -C "$TMP_DIR"

BIN_PATH="${TMP_DIR}/${BIN_NAME}"
if [ ! -f "$BIN_PATH" ]; then
  BIN_PATH="$(find "$TMP_DIR" -type f -name "$BIN_NAME" | head -n 1 || true)"
fi
[ -n "$BIN_PATH" ] || die "Binary not found inside archive"

INSTALL_DIR="$(pick_install_dir)"
DEST="${INSTALL_DIR}/${BIN_NAME}"

if [ -e "$DEST" ] && [ "$FORCE" -ne 1 ]; then
  die "${DEST} already exists. Use --force to overwrite."
fi

run mkdir -p "$INSTALL_DIR"
[ -w "$INSTALL_DIR" ] || die "No write permission for ${INSTALL_DIR}. Use --install-dir <dir>."

TMP_DEST="${DEST}.tmp.$$"
rm -f "$TMP_DEST"

log "Installing to ${INSTALL_DIR}..."
run cp "$BIN_PATH" "$TMP_DEST"
run chmod +x "$TMP_DEST"
run mv "$TMP_DEST" "$DEST"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "${INSTALL_DIR} is not in your PATH" ;;
esac

log "----------------------------------------"
log "${BIN_NAME} ${RESOLVED_VERSION} installed successfully!"
log "Run '${BIN_NAME} --help' to get started."
log "----------------------------------------"
