# ghidra-llm: Dockerized Ghidra → text → ask Claude

A small pipeline that runs Ghidra **headlessly inside Docker** against any binary and
**spits out plain-text disassembly and decompilation files**. Those files can then be
**ingested by Claude** (or any LLM) to answer questions about the program — what it does,
what a given function means, where a string is used, and so on.

```
binary ──▶ [ dockerized Ghidra headless ] ──▶ program_info.txt
                                              disassembly.txt   ──▶ ask Claude
                                              decompilation.c
```

This reuses the repo's existing Docker image (`docker/Dockerfile`, `MODE=headless`) and adds:

| File | Purpose |
|------|---------|
| `scripts/ExportProgramForLLM.java` | Ghidra headless script that exports the text files. Mounted at runtime, so you can edit it without rebuilding the image. |
| `analyze.sh` | Host wrapper: `binary → text files` via the Docker image. |
| `README.md` | This document. |

## 1. Build the Ghidra Docker image (one time, from this source tree)

The Docker image is built from a Ghidra **release** produced from this source tree. This is
the heavy, one-time step (~20+ minutes).

```bash
# From the repo root:
./gradlew buildGhidra

# Unpack the release that was just built:
cd build/dist
unzip ghidra_*.zip
cd ghidra_*/

# Build the Docker image (the release ships its own docker/ dir):
./docker/build-docker-image.sh
```

This produces an image tagged `ghidra/ghidra:<version>_<release>` (e.g.
`ghidra/ghidra:11.x_DEV`). `analyze.sh` derives this same tag automatically from
`Ghidra/application.properties`; you can also pass an explicit tag as the 3rd argument.

## 2. Analyze a binary → text files

```bash
./ghidra-llm/analyze.sh /path/to/binary
```

Output lands in `./ghidra-out/<binary-name>/`:

- `program_info.txt` — arch, compiler, image base, address range, hashes, memory map.
- `disassembly.txt` — full instruction listing, grouped by function (`address  bytes  instr`).
- `decompilation.c` — decompiled C for each non-thunk, non-external function.

Options:

```bash
# custom output dir and/or explicit image tag
./ghidra-llm/analyze.sh /path/to/binary ./out ghidra/ghidra:11.x_DEV

# skip decompilation (much faster on very large binaries)
NODECOMPILE=1 ./ghidra-llm/analyze.sh /path/to/binary

# give the analyzer more heap
MAXMEM=8G ./ghidra-llm/analyze.sh /path/to/binary
```

> **Permissions note:** the container runs as user `ghidra` (uid/gid `1001`). `analyze.sh`
> `chmod 777`s the output directory so the container can write to it. If you choose a custom
> output dir on a restricted filesystem, make sure uid `1001` can write to it.

## 3. Ask Claude about the program

Point Claude Code at the output directory and ask questions. It reads `program_info.txt`
for context, `decompilation.c` for behavior, and `disassembly.txt` for instruction-level
detail.

Example prompts:

- "Read `ghidra-out/ls/` and summarize what this binary does."
- "In `decompilation.c`, what does function `FUN_00401000` do? Walk me through it."
- "Where is the string `\"license\"` referenced, and what is the surrounding logic?"
- "Does this binary make any network or file-system calls? Cite the functions."
- "Find anything that looks like a hardcoded credential or key check."

For large programs, the decompilation file is the most useful starting point; ask Claude to
read it first and only dip into `disassembly.txt` when instruction-level detail is needed.

## How it runs (under the hood)

`analyze.sh` invokes the existing headless entrypoint:

```bash
docker run --rm --env MODE=headless \
  --volume <binary>:/work/input/<name>:ro \
  --volume ghidra-llm/scripts:/work/scripts:ro \
  --volume <output>:/work/out \
  ghidra/ghidra:<tag> \
  /home/ghidra/proj llmproj \
    -import /work/input/<name> \
    -scriptPath /work/scripts \
    -postScript ExportProgramForLLM.java /work/out \
    -readOnly -deleteProject
```

A throwaway Ghidra project is created inside the container's writable `/home/ghidra` and
deleted afterward (`-deleteProject`); only the exported text files persist on the host.

## Verifying without Docker (optional)

After `./gradlew buildGhidra` you can run the export script directly to sanity-check it:

```bash
build/dist/ghidra_*/support/analyzeHeadless /tmp/p t \
  -import /bin/ls \
  -scriptPath ghidra-llm/scripts \
  -postScript ExportProgramForLLM.java /tmp/out \
  -deleteProject
ls -la /tmp/out   # program_info.txt, disassembly.txt, decompilation.c
```
