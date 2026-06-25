#!/usr/bin/env bash
## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
#
# analyze.sh - run the dockerized Ghidra headless analyzer against a binary and
# export plain-text disassembly + decompilation files for LLM (Claude) ingestion.
#
# Usage:
#   ./ghidra-llm/analyze.sh <binary> [output_dir] [image_tag]
#
# Arguments:
#   <binary>      Path to the binary/executable to analyze (required).
#   [output_dir]  Where to write the text files. Default: ./ghidra-out/<binary-basename>
#   [image_tag]   Docker image to use. Default: derived from Ghidra/application.properties,
#                 i.e. ghidra/ghidra:<version>_<release> (same scheme as build-docker-image.sh).
#
# Environment:
#   NODECOMPILE=1   Skip decompilation (faster on very large binaries).
#   MAXMEM=4G       Override the JVM heap given to the headless analyzer.
#
# Produces in <output_dir>:
#   program_info.txt  disassembly.txt  decompilation.c
#-------------------------------------------------------------------------------

set -euo pipefail

SCRIPT_FILE="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SCRIPT_DIR="${SCRIPT_FILE%/*}"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
	echo "Usage: $0 <binary> [output_dir] [image_tag]" >&2
	exit 1
}

# --- check docker ------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
	echo "ERROR: docker not found on PATH. Please install Docker." >&2
	exit 1
fi

# --- args --------------------------------------------------------------------
BINARY="${1:-}"
[ -n "${BINARY}" ] || usage
if [ ! -f "${BINARY}" ]; then
	echo "ERROR: binary not found: ${BINARY}" >&2
	exit 1
fi
BINARY_ABS="$(readlink -f "${BINARY}")"
BINARY_NAME="$(basename "${BINARY_ABS}")"

OUTPUT_DIR="${2:-${REPO_ROOT}/ghidra-out/${BINARY_NAME}}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_ABS="$(readlink -f "${OUTPUT_DIR}")"

# --- resolve image tag -------------------------------------------------------
IMAGE_TAG="${3:-}"
if [ -z "${IMAGE_TAG}" ]; then
	APP_PROPS="${REPO_ROOT}/Ghidra/application.properties"
	if [ -f "${APP_PROPS}" ]; then
		# Same derivation as docker/build-docker-image.sh
		source <(sed 's/\.\|\(=.*\)/_\1/g;s/_=/=/' "${APP_PROPS}") &>/dev/null || true
		IMAGE_TAG="ghidra/ghidra:${application_version}_${application_release_name}"
	else
		IMAGE_TAG="ghidra/ghidra:latest"
	fi
fi

if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
	echo "ERROR: docker image '${IMAGE_TAG}' not found locally." >&2
	echo "       Build it first (see ghidra-llm/README.md):" >&2
	echo "         ./gradlew buildGhidra" >&2
	echo "         cd build/dist && unzip ghidra_*.zip && cd ghidra_*/" >&2
	echo "         ./docker/build-docker-image.sh" >&2
	echo "       Or pass an explicit image tag as the 3rd argument." >&2
	exit 1
fi

# --- container user must be able to write the output dir (uid 1001) ----------
chmod 777 "${OUTPUT_ABS}" 2>/dev/null || \
	echo "WARN: could not chmod 777 ${OUTPUT_ABS}; container (uid 1001) may fail to write." >&2

POST_ARGS="/work/out"
if [ "${NODECOMPILE:-0}" = "1" ]; then
	POST_ARGS="/work/out nodecompile"
fi

echo "Image:   ${IMAGE_TAG}"
echo "Binary:  ${BINARY_ABS}"
echo "Output:  ${OUTPUT_ABS}"
echo "Running Ghidra headless analysis (this can take a while on large binaries)..."

# shellcheck disable=SC2086
docker run --rm \
	--env MODE=headless \
	--env MAXMEM="${MAXMEM:-4G}" \
	--volume "${BINARY_ABS}:/work/input/${BINARY_NAME}:ro" \
	--volume "${SCRIPT_DIR}/scripts:/work/scripts:ro" \
	--volume "${OUTPUT_ABS}:/work/out" \
	"${IMAGE_TAG}" \
	/home/ghidra/proj llmproj \
	-import "/work/input/${BINARY_NAME}" \
	-scriptPath /work/scripts \
	-postScript ExportProgramForLLM.java ${POST_ARGS} \
	-readOnly \
	-deleteProject

echo
echo "Done. Exported files:"
ls -la "${OUTPUT_ABS}"
echo
echo "Now ask Claude about the program by pointing it at: ${OUTPUT_ABS}"
echo "  e.g. \"Read ${OUTPUT_ABS} and tell me what this binary does.\""
