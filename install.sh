#!/usr/bin/env sh
# Installs the `hampp` CLI: prebuilt release binary (checksum verified), else `cargo install`.
set -eu
REPO="${HAMPP_REPO:-xoBase/hampp}"
PREFIX="${HAMPP_PREFIX:-$HOME/.local/bin}"

case "$REPO" in *@@*) echo "This copy of install.sh has no repository set (HAMPP_REPO)." >&2; exit 2;; esac

os="$(uname -s)"; arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
  Darwin-arm64) target="aarch64-apple-darwin" ;;
  Darwin-x86_64) target="x86_64-apple-darwin" ;;
  *) target="" ;;
esac

fallback() {
  command -v cargo >/dev/null 2>&1 || { echo "No prebuilt binary for $os-$arch and cargo is not installed." >&2; exit 1; }
  echo "Building from source with cargo ..."
  cargo install --git "https://github.com/$REPO" hampp-cli --locked
  exit 0
}

[ -n "$target" ] || fallback
command -v curl >/dev/null 2>&1 || fallback
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/latest/download"
curl -fsSL "$base/hampp-$target.tar.gz" -o "$tmp/h.tar.gz" || fallback
curl -fsSL "$base/hampp-$target.tar.gz.sha256" -o "$tmp/h.sha256" || fallback
want="$(cut -d' ' -f1 "$tmp/h.sha256")"
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/h.tar.gz" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$tmp/h.tar.gz" | cut -d' ' -f1)"; fi
[ "$want" = "$got" ] || { echo "checksum mismatch, refusing to install" >&2; exit 1; }
mkdir -p "$PREFIX"
tar -xzf "$tmp/h.tar.gz" -C "$tmp"
install -m 0755 "$tmp/hampp" "$PREFIX/hampp"
echo "installed $PREFIX/hampp"
case ":$PATH:" in *":$PREFIX:"*) ;; *) echo "note: add $PREFIX to your PATH" ;; esac
