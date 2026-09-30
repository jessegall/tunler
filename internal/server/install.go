package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// binaryName matches the client binaries produced by `make release`,
// e.g. "tunler-linux-amd64" or "tunler-windows-amd64.exe".
var binaryName = regexp.MustCompile(`^tunler(-server)?-[a-z0-9]+-[a-z0-9]+(\.exe)?(\.sha256)?$`)

// handleDownload serves a cross-compiled client binary from the bin dir.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, name string) {
	if !s.downloadAuthorized(w, r) {
		return
	}
	if s.cfg.BinDir == "" {
		http.Error(w, "downloads not configured on this server", http.StatusNotFound)
		return
	}
	if !binaryName.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.cfg.BinDir, name)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, fmt.Sprintf("no binary %q on this server (upload it to the server's bin directory)", name), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

// handleInstall serves a self-contained installer script that detects the
// machine's OS/architecture and downloads the matching client binary.
func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	if !s.downloadAuthorized(w, r) {
		return
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	// Only reflect the request host when it's this server's own domain (or a
	// loopback in dev); otherwise a poisoned Host header could shape the
	// script served to a victim.
	host := r.Host
	if h := stripPort(host); h != s.cfg.Domain && !isLoopback(h) {
		host = s.cfg.Domain
	}
	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprint(w, strings.ReplaceAll(installScript, "{{BASE}}", scheme+"://"+host))
}

func unauthorizedDownload(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="tunler"`)
	http.Error(w, "authentication required (set TUNLER_PASSWORD and use curl -u tunler:$TUNLER_PASSWORD)", http.StatusUnauthorized)
}

func isLoopback(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

const installScript = `#!/bin/sh
# tunler client installer, served by your own tunler server.
#   curl -fsSL {{BASE}}/install | sh
set -eu

BASE="{{BASE}}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) echo "unsupported OS: $OS (on Windows, download $BASE/dl/tunler-windows-amd64.exe manually)" >&2; exit 1 ;;
esac

URL="$BASE/dl/tunler-$OS-$ARCH"

# Pick an install dir: /usr/local/bin if writable, else ~/.local/bin.
DIR="/usr/local/bin"
if [ ! -w "$DIR" ]; then
  DIR="$HOME/.local/bin"
  mkdir -p "$DIR"
fi

# If the server requires a password for downloads, set TUNLER_PASSWORD and it
# is passed through as HTTP basic auth (harmless when auth isn't required).
PASS="${TUNLER_PASSWORD:-}"
fetch() {
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$PASS" ]; then curl -fsSL -u "tunler:$PASS" -o "$1" "$2"; else curl -fsSL -o "$1" "$2"; fi
  elif [ -n "$PASS" ]; then wget -q --user=tunler --password="$PASS" -O "$1" "$2"
  else wget -qO "$1" "$2"; fi
}

echo "downloading $URL"
TMP=$(mktemp)
fetch "$TMP" "$URL"

# Verify the checksum when a sha256 tool is available.
SUMTOOL=""
if command -v sha256sum >/dev/null 2>&1; then SUMTOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SUMTOOL="shasum -a 256"; fi
if [ -n "$SUMTOOL" ]; then
  SUMTMP=$(mktemp)
  if fetch "$SUMTMP" "$URL.sha256" 2>/dev/null; then
    EXPECTED=$(awk "{print \$1}" "$SUMTMP")
    ACTUAL=$($SUMTOOL "$TMP" | awk "{print \$1}")
    if [ "$EXPECTED" != "$ACTUAL" ]; then
      echo "checksum mismatch, aborting" >&2
      rm -f "$TMP" "$SUMTMP"; exit 1
    fi
    echo "checksum ok"
  fi
  rm -f "$SUMTMP"
fi

chmod +x "$TMP"
mv "$TMP" "$DIR/tunler"

# Bind the client to the server it was installed from, so --host can be
# omitted entirely. Reinstalling from another server overwrites this.
# (Paths mirror Go's os.UserConfigDir.)
if [ "$OS" = "darwin" ]; then
  CFG_DIR="$HOME/Library/Application Support/tunler"
else
  CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/tunler"
fi
mkdir -p "$CFG_DIR"
HOST="${BASE#*://}"
printf '%s\n' "$HOST" > "$CFG_DIR/server"
echo "default server: $HOST"

echo "installed: $DIR/tunler"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "note: $DIR is not in your PATH" ;;
esac
echo "get started:  tunler login <email>"
echo "then:         tunler 8000"
`
