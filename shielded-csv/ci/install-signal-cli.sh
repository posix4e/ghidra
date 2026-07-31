#!/usr/bin/env bash
# Install a pinned, checksum-verified signal-cli into ~/.local (bin + lib).
#
# signal-cli is the Signal payment transport for shielded-csv (scsv-transport):
# a coin bundle is sent as a Signal message attachment through a local signal-cli
# daemon in HTTP JSON-RPC mode. There is no mock daemon.
#
# CHECKSUM POLICY (read this): the download is verified against a pinned SHA256
# and the script FAILS CLOSED if the hash is unset — it never installs an
# unverified binary. The pinned hash is intentionally empty in the committed
# script because this repository's authoring environment blocks egress to
# github.com (organization egress policy), so the release tarball could not be
# downloaded and hashed here. Before first use, pin the hash for the version
# below from a trusted machine:
#
#     v=0.13.18
#     curl -fSL -o signal-cli.tar.gz \
#       "https://github.com/AsamK/signal-cli/releases/download/v${v}/signal-cli-${v}.tar.gz"
#     sha256sum signal-cli.tar.gz     # cross-check against the release page
#
# then set SCSV_SIGNALCLI_SHA256=<hash> (env) or edit SHA256 below. signal-cli
# needs Java 21+ (this environment already has it: `java -version`).
set -euo pipefail

VERSION="${SCSV_SIGNALCLI_VERSION:-0.13.18}"
# Pin per release (see header). Overridable via env for locked-down installs.
SHA256="${SCSV_SIGNALCLI_SHA256:-}"
PREFIX="${SCSV_SIGNALCLI_PREFIX:-$HOME/.local}"
BASE_URL="https://github.com/AsamK/signal-cli/releases/download/v${VERSION}"
TARBALL="signal-cli-${VERSION}.tar.gz"

if ! command -v java >/dev/null 2>&1; then
  echo "signal-cli needs Java 21+, but 'java' is not on PATH" >&2
  exit 1
fi

if command -v signal-cli >/dev/null 2>&1 && signal-cli --version 2>/dev/null | grep -q "${VERSION}"; then
  echo "signal-cli ${VERSION} already installed: $(command -v signal-cli)"
  exit 0
fi

if [ -z "$SHA256" ]; then
  cat >&2 <<EOF
refusing to install signal-cli ${VERSION} without a pinned SHA256.
Set SCSV_SIGNALCLI_SHA256=<hash> (see the header of this script for how to
obtain it) and re-run. The script never installs an unverified download.
EOF
  exit 2
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

echo "downloading ${BASE_URL}/${TARBALL}"
curl -fSL --retry 4 --retry-delay 2 -o "$TARBALL" "${BASE_URL}/${TARBALL}"
echo "${SHA256}  ${TARBALL}" | sha256sum -c -

tar -xzf "$TARBALL"
mkdir -p "${PREFIX}/bin" "${PREFIX}/lib"
# The tarball unpacks to signal-cli-<version>/{bin,lib}.
cp -r "signal-cli-${VERSION}/lib/." "${PREFIX}/lib/"
install -m 0755 "signal-cli-${VERSION}/bin/signal-cli" "${PREFIX}/bin/"

echo "installed to ${PREFIX}/bin:"
"${PREFIX}/bin/signal-cli" --version || true
cat <<'EOF'
ensure it is on PATH: export PATH="$HOME/.local/bin:$PATH"

Register an account (needs a real phone number; cannot run in CI):
  signal-cli -a +1XXXXXXXXXX register        # then verify with the SMS code:
  signal-cli -a +1XXXXXXXXXX verify 123456
Run the JSON-RPC daemon scsv talks to:
  signal-cli -a +1XXXXXXXXXX daemon --http 127.0.0.1:8080
Point the CLI at it:
  export SCSV_SIGNAL_RPC=http://127.0.0.1:8080/api/v1/rpc
  export SCSV_SIGNAL_ACCOUNT=+1XXXXXXXXXX
EOF
