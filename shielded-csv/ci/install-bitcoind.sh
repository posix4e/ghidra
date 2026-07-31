#!/usr/bin/env bash
# Install a pinned, checksum-verified Bitcoin Core into ~/.local/bin.
#
# The shielded-csv test suite and demos run against a REAL bitcoind
# (regtest). There is no mock chain and no skip path: if bitcoind is
# missing, tests fail and point here.
#
# Hashes below are from https://bitcoincore.org/bin/bitcoin-core-31.1/SHA256SUMS.
set -euo pipefail

VERSION=31.1
BASE_URL="https://bitcoincore.org/bin/bitcoin-core-${VERSION}"
PREFIX="${SCSV_BITCOIND_PREFIX:-$HOME/.local}"

case "$(uname -m)" in
  x86_64)  ARCH=x86_64-linux-gnu;  SHA256=b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e ;;
  aarch64) ARCH=aarch64-linux-gnu; SHA256=dcf1873f2208ba4f962f3398d47e154c39c0084be8f4553e05c940d0ace3d004 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if command -v bitcoind >/dev/null 2>&1 && bitcoind --version | head -1 | grep -q "v${VERSION}"; then
  echo "bitcoind v${VERSION} already installed: $(command -v bitcoind)"
  exit 0
fi

TARBALL="bitcoin-${VERSION}-${ARCH}.tar.gz"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "downloading ${BASE_URL}/${TARBALL}"
curl -fSL --retry 4 --retry-delay 2 -o "$TARBALL" "${BASE_URL}/${TARBALL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -

tar -xzf "$TARBALL"
mkdir -p "${PREFIX}/bin"
install -m 0755 "bitcoin-${VERSION}/bin/bitcoind" "bitcoin-${VERSION}/bin/bitcoin-cli" "${PREFIX}/bin/"

echo "installed to ${PREFIX}/bin:"
"${PREFIX}/bin/bitcoind" --version | head -1
echo 'ensure it is on PATH: export PATH="$HOME/.local/bin:$PATH"'
