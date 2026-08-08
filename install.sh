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
  case "$target" in
    *-pc-windows-*) extension=zip ;;
    *) extension=tar.gz ;;
  esac
  printf 'https://github.com/%s/releases/download/%s/%s-%s.%s' \
    "$REPO" "$version" "$BIN_NAME" "$target" "$extension"
}

sha256_digest() {
  file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | cut -d' ' -f1
    return
  fi

  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | cut -d' ' -f1
    return
  fi

  die "sha256sum or shasum is required to verify release checksums"
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
    MINGW*|MSYS*|CYGWIN*)
      case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) die "Unsupported architecture: $arch" ;;
      esac
      printf '%s\n' "${arch}-pc-windows-msvc"
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
  case "$target" in
    *-pc-windows-*) extension=zip ;;
    *) extension=tar.gz ;;
  esac
  out="${TMP_DIR}/${BIN_NAME}-${target}.${extension}"
  part="${out}.partial"

  [ "$VERBOSE" -eq 1 ] && log "Trying ${target}: ${url}"

  rm -f "$part"

  set +e
  if [ "$VERBOSE" -eq 1 ]; then
    curl -fL --progress-bar -o "$part" "$url" 2>"${TMP_DIR}/curl_stderr"
    rc=$?
  else
    curl -fsSL -o "$part" "$url" 2>"${TMP_DIR}/curl_stderr"
    rc=$?
  fi
  set -e

  if [ "$rc" -ne 0 ]; then
    rm -f "$part"
    if [ "$rc" -eq 22 ]; then
      return 1  # 404 / not found — expected for fallback targets
    fi
    # Network/SSL error — capture details for final error message
    errmsg=$(tr '\n' ' ' < "${TMP_DIR}/curl_stderr" 2>/dev/null || true)
    printf '%s\n' "network-error:${target}:${rc}:${errmsg}" >&2
    return 2
  fi

  # Every published archive must have an adjacent checksum. Never install an
  # archive whose checksum is unavailable, malformed, or mismatched.
  case "$extension" in
    zip) sha_url="${url%.zip}.sha256" ;;
    tar.gz) sha_url="${url%.tar.gz}.sha256" ;;
  esac
  sha_file="${part}.sha256"
  if ! curl -fsSL -o "$sha_file" "$sha_url" 2>/dev/null; then
    rm -f "$part" "$sha_file"
    printf '%s\n' "integrity-error:${target}:checksum file is unavailable" >&2
    return 3
  fi

  expected=$(cut -d' ' -f1 < "$sha_file" 2>/dev/null || true)
  if ! printf '%s\n' "$expected" | grep -Eq '^[[:xdigit:]]{64}$'; then
    rm -f "$sha_file"
    rm -f "$part"
    printf '%s\n' "integrity-error:${target}:checksum file is malformed" >&2
    return 3
  fi

  actual=$(sha256_digest "$part")
  if [ "$actual" != "$expected" ]; then
    rm -f "$part" "$sha_file"
    printf '%s\n' "integrity-error:${target}:checksum mismatch" >&2
    return 3
  fi
  rm -f "$sha_file"
  [ "$VERBOSE" -eq 1 ] && log "Checksum verified for ${target}"

  if [ "$extension" = zip ]; then
    unzip -tq "$part" >/dev/null 2>&1 || {
      rm -f "$part"
      printf '%s\n' "integrity-error:${target}:archive is invalid" >&2
      return 3
    }
  else
    tar -tzf "$part" >/dev/null 2>&1 || {
      rm -f "$part"
      printf '%s\n' "integrity-error:${target}:archive is invalid" >&2
      return 3
    }
  fi

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

need uname

REQUESTED_VERSION="$(normalize_version "$REQUESTED_VERSION")"

log "Detecting operating system and architecture..."

OS="$(uname -s)"
ARCH="$(uname -m)"

CANDIDATES="$(candidate_targets "$OS" "$ARCH")"
INSTALL_DIR="$(pick_install_dir)"
DEST="${INSTALL_DIR}/${BIN_NAME}"
case "$CANDIDATES" in
  *-pc-windows-*) DEST="${DEST}.exe" ;;
esac

if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] No network requests or filesystem changes will be made."
  if [ "$REQUESTED_VERSION" = "latest" ]; then
    log "[dry-run] Would query GitHub Releases for the latest version."
    VERSION_LABEL="<latest release>"
  else
    VERSION_LABEL="$REQUESTED_VERSION"
  fi

  log "[dry-run] Version: ${VERSION_LABEL}"
  log "[dry-run] Candidate targets: $(printf '%s ' $CANDIDATES)"
  for candidate in $CANDIDATES; do
    if [ "$REQUESTED_VERSION" = "latest" ]; then
      log "[dry-run] Would download and verify $(build_url '<latest release>' "$candidate") after resolving the release version."
    else
      log "[dry-run] Would download and verify $(build_url "$REQUESTED_VERSION" "$candidate")"
    fi
  done
  log "[dry-run] Would extract the selected archive and atomically install ${DEST}"
  if [ -e "$DEST" ] && [ "$FORCE" -ne 1 ]; then
    warn "${DEST} already exists; a real install would require --force."
  fi
  exit 0
fi

need curl
need sed
need head
need grep
need mktemp
need cp
need chmod
need mkdir
need mv
need rm
case "$CANDIDATES" in
  *-pc-windows-*) need unzip ;;
  *) need tar ;;
esac

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

ARCHIVE_FILE=""
SELECTED_TARGET=""
NETWORK_ERROR=""
INTEGRITY_ERROR=""

for candidate in $CANDIDATES; do
  rc=0
  ARCHIVE_FILE="$(download_asset "$RESOLVED_VERSION" "$candidate" 2>"${TMP_DIR}/dl_err")" || rc=$?
  if [ "$rc" -eq 0 ]; then
    SELECTED_TARGET="$candidate"
    break
  elif [ "$rc" -eq 2 ]; then
    NETWORK_ERROR="$(cat "${TMP_DIR}/dl_err" 2>/dev/null || true)"
  elif [ "$rc" -eq 3 ]; then
    INTEGRITY_ERROR="$(cat "${TMP_DIR}/dl_err" 2>/dev/null || true)"
    break
  fi
done

if [ -z "$ARCHIVE_FILE" ]; then
  if [ -n "$INTEGRITY_ERROR" ]; then
    printf 'Error: release integrity verification failed for %s\n' "$RESOLVED_VERSION" >&2
    if echo "$INTEGRITY_ERROR" | grep -q '^integrity-error:'; then
      printf '  Target : %s\n' "$(echo "$INTEGRITY_ERROR" | cut -d: -f2)" >&2
      printf '  Reason : %s\n' "$(echo "$INTEGRITY_ERROR" | cut -d: -f3-)" >&2
    fi
  elif [ -n "$NETWORK_ERROR" ]; then
    printf 'Error: network failure downloading %s\n' "$RESOLVED_VERSION" >&2
    if echo "$NETWORK_ERROR" | grep -q '^network-error:'; then
      printf '  Target : %s\n' "$(echo "$NETWORK_ERROR" | cut -d: -f2)" >&2
      printf '  curl exit code : %s\n' "$(echo "$NETWORK_ERROR" | cut -d: -f3)" >&2
      printf '  curl error     : %s\n' "$(echo "$NETWORK_ERROR" | cut -d: -f4-)" >&2
    fi
  else
    printf 'Error: no matching release asset found for %s\n' "$RESOLVED_VERSION" >&2
    printf 'Tried targets:\n' >&2
    for t in $CANDIDATES; do
      printf '  - %s\n' "$t" >&2
    done
  fi
  exit 1
fi

log "Selected target: ${SELECTED_TARGET}"
log "Extracting archive..."
case "$SELECTED_TARGET" in
  *-pc-windows-*) run unzip -q "$ARCHIVE_FILE" -d "$TMP_DIR" ;;
  *) run tar -xzf "$ARCHIVE_FILE" -C "$TMP_DIR" ;;
esac

BIN_PATH="${TMP_DIR}/${BIN_NAME}"
case "$SELECTED_TARGET" in
  *-pc-windows-*) BIN_PATH="${BIN_PATH}.exe" ;;
esac
if [ ! -f "$BIN_PATH" ]; then
  case "$SELECTED_TARGET" in
    *-pc-windows-*) search_name="${BIN_NAME}.exe" ;;
    *) search_name="$BIN_NAME" ;;
  esac
  BIN_PATH="$(find "$TMP_DIR" -type f -name "$search_name" | head -n 1 || true)"
fi
[ -n "$BIN_PATH" ] || die "Binary not found inside archive"

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
