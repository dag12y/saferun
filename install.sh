#!/bin/sh
set -eu

if (set -o pipefail) 2>/dev/null; then
    set -o pipefail
fi

VERSION=${SAFERUN_VERSION:-v1.0.5}
RELEASE_BASE_URL=${SAFERUN_RELEASE_BASE_URL:-https://github.com/dag12y/saferun/releases/download}
INSTALL_DIR=${SAFERUN_INSTALL_DIR:-"$HOME/.local/bin"}

error() {
    printf '%s\n' "Error: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "${TEMP_DIR:-}" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

command -v curl >/dev/null 2>&1 || error "curl is required to install SafeRun."
command -v uname >/dev/null 2>&1 || error "uname is required to detect the platform."

OS=$(uname -s)
case "$OS" in
    Linux) RELEASE_OS=linux; OS_LABEL=Linux ;;
    Darwin) RELEASE_OS=darwin; OS_LABEL=macOS ;;
    *) error "unsupported operating system: $OS (supported: Linux and macOS)." ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) RELEASE_ARCH=amd64 ;;
    arm64|aarch64) RELEASE_ARCH=arm64 ;;
    *) error "unsupported architecture: $ARCH (supported: amd64 and arm64)." ;;
esac

BINARY_NAME="saferun-${RELEASE_OS}-${RELEASE_ARCH}"
RELEASE_URL="${RELEASE_BASE_URL%/}/${VERSION}"
BINARY_URL="${RELEASE_URL}/${BINARY_NAME}"
CHECKSUMS_URL="${RELEASE_URL}/SHA256SUMS"

printf '%s\n' 'SafeRun Installer' '-----------------' "Version: $VERSION" "OS: $OS_LABEL" "Architecture: $RELEASE_ARCH" '' 'Downloading SafeRun...'

TEMP_DIR=$(mktemp -d 2>/dev/null) || error 'unable to create a temporary directory.'
DOWNLOADED_BINARY="$TEMP_DIR/$BINARY_NAME"
CHECKSUMS_FILE="$TEMP_DIR/SHA256SUMS"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$DOWNLOADED_BINARY" "$BINARY_URL" || error 'failed to download the SafeRun binary.'
printf '%s\n' 'Downloading checksums...'
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$CHECKSUMS_FILE" "$CHECKSUMS_URL" || error 'failed to download SHA256SUMS.'

EXPECTED_CHECKSUM=$(awk -v name="$BINARY_NAME" '$2 == name { print $1; found = 1; exit } END { if (!found) exit 1 }' "$CHECKSUMS_FILE") || error "SHA256SUMS does not contain $BINARY_NAME."
case "$EXPECTED_CHECKSUM" in
    *[!0123456789abcdefABCDEF]*|'') error "invalid checksum for $BINARY_NAME." ;;
esac

printf '%s\n' 'Verifying SafeRun binary...'
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_CHECKSUM=$(sha256sum "$DOWNLOADED_BINARY" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_CHECKSUM=$(shasum -a 256 "$DOWNLOADED_BINARY" | awk '{print $1}')
else
    error 'no SHA-256 checksum tool found (install sha256sum or shasum).'
fi

if [ "$ACTUAL_CHECKSUM" != "$EXPECTED_CHECKSUM" ]; then
    printf '%s\n' 'Checksum verification failed.' 'Installation aborted.' >&2
    exit 1
fi
printf '%s\n' 'Checksum verified.'

mkdir -p "$INSTALL_DIR" || error "unable to create installation directory: $INSTALL_DIR."
DESTINATION="$INSTALL_DIR/saferun"
STAGED_DESTINATION="$INSTALL_DIR/.saferun-install.$$"
rm -f "$STAGED_DESTINATION"
install -m 0755 "$DOWNLOADED_BINARY" "$STAGED_DESTINATION" || error "unable to install SafeRun to $DESTINATION."
mv -f "$STAGED_DESTINATION" "$DESTINATION" || error "unable to install SafeRun to $DESTINATION."
[ -f "$DESTINATION" ] && [ -x "$DESTINATION" ] || error "installed SafeRun is missing or not executable."

printf '%s\n' '' 'Installation successful.' '' 'Installed to:' "  $DESTINATION" '' 'SafeRun requires Docker for sandboxed package analysis.' '' 'Run:' '' '  saferun setup' '  saferun npm install <package>'

case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*)
        "$DESTINATION" --help >/dev/null 2>&1 || :
        ;;
    *)
        printf '%s\n' '' "$INSTALL_DIR is not currently in your PATH." '' 'Add it with:' '' "  export PATH=\"\$HOME/.local/bin:\$PATH\"" '' 'For permanent configuration, add that line to your shell profile.'
        "$DESTINATION" --help >/dev/null 2>&1 || :
        ;;
esac
